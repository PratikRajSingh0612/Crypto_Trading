# Project 1 Stage 8 — SQLite Persistence and Migrations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** Detailed implementation plan for Stage 8. Implementation status is
recorded only in the master roadmap status table, never in this header, so the
header cannot go stale.
**Planning base:** `b64efb996271305e29d8b6b6c739d4484a4df1d6` (`main` = `HEAD` = merge base)
**Prerequisites:** Stages 1–7 complete and merged
**Goal:** Implement the durable SQLite system of record behind the application
ports that Stages 5–7 defined and exercised only through in-memory doubles:
a WAL-mode, foreign-key-enforcing, `synchronous=FULL`, busy-bounded SQLite
database opened from the existing `database.*` configuration; SQLAlchemy 2.x
mappings kept separate from the canonical Pydantic records; an Alembic
migration tree with one expected head and startup revision checks; short units
of work with revision compare-and-swap; the lifecycle, retry-decision,
invocation-event, availability-observation, diagnostic, causal-edge,
base-registry and artifact-owner tables with their constraints and indexes,
the frozen configuration-snapshot columns of the experiment row; and the
persistence-side recovery reads the Stage 7 reconciler needs — proven against
real temporary databases, separate connections, interrupted transactions and
Windows file locking, and composed with the existing application operations
without finalizing an artifact or reporting a successful run.
**Architecture:** `crypto_lab.persistence` implements the application-owned
protocols (`crypto_lab.experiments.ports`, `crypto_lab.adapters.ports`,
`crypto_lab.experiments.supervision_lifecycle.DiagnosticRecorder`,
`crypto_lab.process_supervision.ports.ReconciliationSource`) over SQLAlchemy
Core statements issued through declaratively mapped table metadata. It imports
`domain`, the port modules and the two new registry port modules only; no
existing package imports it (composition is Stage 10's `cli`). Every canonical
record is validated on ingress (the record the caller hands in is already a
strict `CanonicalModel`) and re-validated on egress (each row is projected to a
JSON-mode payload and rebuilt through the record's own validators), so a row can
never bypass a canonical invariant. The unit of work is one deferred SQLite
transaction on one exclusively owned connection: reads see one WAL snapshot,
the first write takes the writer lock, and a busy timeout, a stale-snapshot
upgrade refusal or a unique-key violation surfaces at the write call as the
existing `PERSISTENCE.CONCURRENCY_CONFLICT` failure, never at `commit()` and
never as an exception. Domain models, lifecycle tables, retry semantics,
protocol contracts, hashing profiles and the 35 published schemas are consumed
unchanged.
**Tech stack:** Python 3.12, Pydantic v2 strict models (unchanged), SQLAlchemy
2.x (Core statements over declarative `MetaData`), Alembic (programmatic
`Config` and `command` API; no `alembic.ini`), the stdlib `sqlite3` DBAPI
bundled with the managed CPython 3.12.13 (SQLite library 3.53.1, measured on
the planning host), `hypothesis` for bounded round-trip properties, the closed
`scripts/invoke-uv.ps1` launcher (gaining one profile) and `scripts/verify.ps1`
(gaining one step).
**Spec:** `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md`
(sections 8.1–8.2, 10.4, 11.3, 11.5, 15.2, 15.6, 16–19, 21, 23, 28.1, 28.3,
28.5, 29, 30.3, 33.5 and 33.6 per the roadmap's Stage 8 row; sections 1–9, 24,
27, 31–32 and 34 as the global floor).

## Global Constraints

- Python `>=3.12,<3.13`; runtime dependencies become exactly the four entries
  `alembic`, `pydantic>=2.12,<3`, `pyyaml>=6.0.3,<7` and `sqlalchemy`, with the
  two new ranges chosen in Task 1 as a lower bound plus a next-major upper bound
  (`sqlalchemy>=2.0,<3` and `alembic>=1.13,<2` are the proposed shapes; the exact
  locked versions are whatever the reviewed `uv.lock` records after §2.8's gates,
  never a number this plan asserts). No other dependency, no development-group
  change, no `[tool.mypy]` override, no new pytest marker, no new approved skip
  (the two stay exactly two: `tests/safety/test_uv_launcher.py` symbolic-link
  privilege and `tests/unit/experiments/test_experiment_service.py` same-state
  replay).
- Every command runs through `scripts/invoke-uv.ps1` profiles. The launcher gains
  exactly one profile, `migration-check` (Task 2), and `scripts/verify.ps1` gains
  exactly one step, "Check migrations", between the generated-schema check and
  the test suite; both pins are re-recorded in the same commit (§2.6). No other
  launcher or verifier change.
- Branch coverage floor stays 90 percent in `pyproject.toml`; the complete
  verifier must report at least **98.42 percent branch coverage**, the value
  measured on the planning base (8614 passed, 2 skipped, ten verifier stages green, 19 min 16 s of pytest), with
  `crypto_lab.persistence` and the two new port modules counted.
- Canonical schemas: the registry stays closed at 35 entries and every published
  byte stays identical (roadmap Stage 8 row: "Canonical schema changes: No; ORM
  mappings must conform to accepted canonical types"). No `CanonicalModel`, enum,
  hashing profile (`HashingProfile` stays 12), lifecycle table, diagnostic
  category or error-code pattern changes; the new `PERSISTENCE.*` codes of §2.5
  reading 9 are admitted by the existing open `ErrorCode` pattern. Every task
  runs `schema-generate-check` and proves the 35 digests unchanged.
- Relational migrations: exactly one Alembic revision exists at the end of the
  stage (`r0001_stage8_baseline`), the script directory has exactly one head, the
  mapped metadata and the migrated database agree, and every persistence table is
  one the roadmap's Stage 8 permission names ("database infrastructure, base
  registries, lifecycle state, retry, invocation/event, owner, and recovery
  mappings"); the Stage 9 tables of §1.3 are neither created nor mapped.
- Dependency direction (spec 8, 27.1): `crypto_lab.persistence` imports only
  `crypto_lab.domain`, `crypto_lab.experiments.ports`,
  `crypto_lab.experiments.supervision_lifecycle` (the `DiagnosticRecorder`
  protocol), `crypto_lab.adapters.ports`, `crypto_lab.process_supervision.ports`,
  `crypto_lab.process_supervision.models` (`RunReconciliationFacts`),
  `crypto_lab.artifacts.ownership`, `crypto_lab.datasets`, `crypto_lab.strategy`
  (the two registry records and their new port modules), `crypto_lab.configuration.models`
  (`DatabaseConfig`, `ApplicationConfig`), `crypto_lab.configuration.snapshot`
  (`ConfigSnapshot`, the frozen configuration snapshot record),
  `crypto_lab.configuration.retry_policy` (`retry_policy_from_config`, for the
  queue-edge agreement check of §4.3.1) and itself. It never imports `experiments` services,
  `capabilities`, `cli`, `schema_registry` or a test tree; `domain`, `experiments`,
  `adapters`, `process_supervision`, `strategy`, `capabilities` and
  `configuration` never import it. The Stage 3 import-root allowlist grows by
  exactly `sqlalchemy` and `alembic`, each confined to the modules §2.6 names;
  `sqlite3`, `os`, `sys`, `time`, `io`, `shutil`, `tempfile`, `logging`, `threading`,
  `asyncio`, `ctypes`, `queue`, `subprocess` and `types` appear in no persistence
  module.
- Storage contract (spec 23, 29.1): WAL journal mode, `foreign_keys=ON`,
  `synchronous=FULL` and the configured `busy_timeout` are applied on every
  physical connection and read back before the connection is used; the database
  path is an absolute path composed by the caller from `paths.runtime_root` and
  `database.filename` — nothing in `persistence` reads configuration, the
  environment, the current directory or a home directory; no write transaction is
  ever open across process execution, heartbeat waiting, hashing or unrelated
  file I/O (the unit of work performs in-memory work only, exactly as the Stage 5
  operations do today); a database whose revision, application identity or
  integrity check fails is refused without mutation and is never rebuilt or
  deleted.
- Trust: adapters receive no database path, handle or row; the raw attempt token
  is never a column, a JSON snapshot member or a diagnostic detail (only
  `attempt_token_hash` is stored, exactly as the records carry it); Decimal values
  are stored as canonical decimal text and never as `REAL`; timestamps are stored
  as integer microseconds since the Unix epoch and rendered back through the
  records' own serializers; database `NULL` encodes exactly one domain state per
  column (§3.2) and is never emitted as JSON `null`.
- No real engine, adapter, exchange, market data, backtest, network, credential,
  wallet, tax, UI, LLM, Docker, cloud or server behavior anywhere; no artifact
  finalization, atomic move, `RunManifest`, `CandidateArtifact`, `ArtifactRef`,
  finalization journal, audit sink or success run state; GitNexus stays
  `DISABLED_WITH_EVIDENCE` and is never invoked; no network during verification
  (the two approval-gated acquisition profiles of §2.8 are bootstrap evidence
  only).

---

## 1. Goal, scope and exclusions

### 1.1 Goal

Stage 8 makes SQLite the authoritative local metadata and state registry
(spec 23.1) for everything Stages 5–7 already record: experiments and their
frozen specs, engine-run attempts, command invocations, retry decisions,
invocation-scoped sanitized run events, core-minted diagnostics, runtime
availability observations, the base registries the specification's table map
names (strategy versions, datasets and partitions) and the artifact-owner
registry that Stage 9's artifact tables will reference. It implements the
existing ports over that database, proves the concurrency, constraint,
migration, restart and Windows-locking properties against real temporary
databases, and composes the existing application operations over the durable
repositories. It defines no new canonical contract and no new lifecycle rule.

### 1.2 In scope

| Area | Stage 8 delivers | Owning task |
|---|---|---|
| Dependencies | `sqlalchemy` and `alembic` as runtime dependencies through the offline-first, approval-gated acquisition sequence of §2.8; `uv.lock` regenerated by the launcher, never hand-edited | 1 |
| Database boundary | `SqliteDatabase`: engine construction over an absolute path, the per-connection PRAGMA policy and its read-back verification, connection lifetime, DBAPI-error classification into stable `Result` failures, `database_path` composition from `PathsConfig`/`DatabaseConfig` values the caller supplies, startup integrity and identity checks | 1 |
| Relational schema | Thirteen tables (§3.3): `experiments` (owning the frozen `ConfigSnapshot` columns of reading 22), `engine_slots`, `engine_runs`, `command_invocations`, `run_events`, `retry_decisions`, `runtime_availability_observations`, `diagnostics`, `diagnostic_causes` (the restricted causal-edge relation of reading 23), `strategy_versions`, `datasets`, `dataset_partitions`, `artifact_owners`; their CHECK constraints, unique and partial-unique indexes, restricted foreign keys and immutability triggers; declarative metadata separate from the domain models | 2 |
| Migrations | The Alembic script directory inside the package, the baseline revision `r0001_stage8_baseline`, the programmatic runner (`apply_migrations`, `check_revision`, `expected_head`, `metadata_drift`), the revision-state vocabulary (§6.4), `scripts/verify_migrations.py`, the `migration-check` launcher profile and verifier step | 2 |
| Row codecs | Lossless ingress/egress mapping for every persisted record (§3.2): integer-microsecond timestamps, canonical decimal text, enum text, canonical-JSON snapshot columns, `NULL` ⇔ `MISSING` per column, JSON-mode re-validation on egress | 3 |
| Registries and readers | `SqliteDiagnosticReader` and `SqliteDiagnosticRecorder` (the sole writer of `diagnostic_causes`); `SqliteAvailabilityObservationReader` and the persistence-owned `SqliteAvailabilityObservationWriter`; the persistence-owned `SqliteConfigurationSnapshotWriter` (`freeze`/`get` of the experiment's `ConfigSnapshot`, reading 22); `SqliteStrategyVersionRepository` and `SqliteDatasetRepository` behind the two new registry ports; `SqliteArtifactOwnerRegistry`; the read-only `SqliteDatabase.consistency_report()` of §4.6 | 3 |
| Unit of work and lifecycle repositories | `SqliteUnitOfWork`/`SqliteTransaction`; `SqliteExperimentRepository` (with the `engine_slots` projection), `SqliteEngineRunRepository` (attempts and events), `SqliteCommandInvocationRepository`, `SqliteRetryDecisionRepository`; the port contract suite re-pointed at SQLite | 4 |
| Persistence-side recovery | `SqliteReconciliationSource` for the Stage 7 reconciler; the Stage 7 lifecycle and reconciliation suites re-pointed at SQLite | 5 |
| Concurrency and recovery evidence | The constructible case matrix of §5 over two connections, deterministic barriers, an interrupted writer process, WAL reopen and Windows file locks | 6 |
| Integration | The Stage 5 in-memory flow and a supervised fake-adapter run composed over the durable repositories, with restart reconciliation over the real database and no success state | 7 |
| Boundaries and status | `tests/safety/test_stage8_boundaries.py`, the Stage 8 focused checks in the verification guide, README, roadmap status row and the closed-world pins of §2.6 | 8 |

### 1.3 Out of scope

Stage 8 does not deliver, map or migrate any of the following. Each row names
the stage that owns it under the roadmap's permission columns.

| Excluded | Reason | Owner |
|---|---|---|
| `candidate_artifacts`, `artifact_refs`, `run_artifacts`, `run_manifests`, `finalization_journal`, `audit_events` (spec 23.3.1) | Artifact finalization, journals, manifests and audit are Stage 9's relational increments; the canonical records they persist (`CandidateArtifact`, `ArtifactRef`, `RunManifest`, `AuditEvent`) are Stage 9 canonical additions and stay in `_DEFERRED_DEFINITIONS` | 9 |
| `adapter_validation_results` and `sanitized_adapter_result_manifests` (spec 23.3.1) | Both records are returned in memory today inside `SemanticReconciliation` and no port writes or reads them; the sanitized manifest references a finalized `EVIDENCE` artifact only Stage 9 can produce, and the roadmap's Stage 8 permission names "invocation/event" and "owner" mappings while Stage 9's names "manifest" and "provenance". Declared ruling: both tables are Stage 9's, overriding the Stage 6 plan's matrix D cell "Stage 8 persists" for the sanitized manifest (§1.5 note 7) | 9 |
| `Diagnostic` rows derived from adapter-authored `AdapterDiagnostic` values | Minting a `DiagnosticId` for an adapter diagnostic needs an identity rule (a hashing-profile or category mapping) that is a canonical decision Stage 8 may not make; core diagnostics cite adapter diagnostics through `details` today | 9 |
| Attaching `PROCESS.PID_REUSE_DETECTED` to a `RUNNING` invocation that stays `RUNNING` | `assert_write_once_enrichment` refuses a non-terminal enrichment (`ENRICHMENT_NOT_TERMINAL`); closing it needs a new `experiments` operation or a widened domain rule, not a mapping. Re-deferred with the Stage 7 wording (§1.4) | 9 or a corrective plan |
| Persisting `ExperimentAggregationResult.reason_codes` | Spec 23.3.1 names no table; `aggregate_experiment` persists only the experiment's terminal state; the reasons are Stage 9 audit material (spec 30.3) | 9 |
| Producing the `ConfigSnapshot` in production (loading and validating the configuration file, calling `snapshot_configuration`, calling the freeze writer before `queue_experiment`) | The snapshot's producer is the composition root; Stage 8 owns the columns, the persistence-owned writer, the queue-edge guard and the tests that exercise them with explicit test configurations — `ApplicationConfig()` in C-32 and `retrying_config()` in Task 7 (§7.1.1) — never by changing the defaults (reading 22, §3.3.1, §4.3.1, §4.4, Task 7) | 10 |
| Writing `RuntimeAvailabilityObservation` rows from a `describe` result in production | `describe_availability_observation` is a pure projection; the Stage 7 plan assigns minting and refresh to Stage 10. Stage 8 provides the persistence-owned writer the composition root and the tests use | 10 |
| Composition, configuration loading, the startup reconciliation order of spec 29.2 (lease, journals, requeue), a `db migrate` command, the production `Clock` and `IdentitySource` | Stage 10 CLI composition and scheduling | 10 |
| A `finalization_deadline_utc` column | The field is forced `MISSING` by today's validator (`EngineRunRecord._validate_finalization_deadline`: "absent throughout Stage 5; Stage 9 snapshots it"); no Stage 8 writer can populate it, so no column exists and the codec refuses a present value (§3.2 rule N4). Stage 9 adds the nullable column. `stderr_artifact_id` is different: the record admits it on every terminal state as a write-once enrichment (`_ENRICHABLE_FIELDS`, `enrich_invocation`), so Stage 8 maps it to a nullable column without a foreign key (§3.3.4) and Stage 9 adds the `artifact_refs` key and the `EVIDENCE`/owner rule | 9 |
| The `artifact_refs` foreign key and owner/purpose validation of `stderr_artifact_id` | Requires the Stage 9 `artifact_refs` table; the column exists in Stage 8 with a terminal-only CHECK only | 9 |
| A second implementation of `resolve_causal_closure`, any repository-side traversal, any DB-side `now()` default, any wall-clock read | Forbidden by the Stage 5 guards and the specification's clock rule | — |
| Retention, deletion or export commands; backup tooling | Spec 23.3.1 retention and spec 29.5 backup belong to later planning; Stage 8 issues no `DELETE` other than the `engine_slots` projection rewrite of §4.3 (a pre-`QUEUED` spec change) and offers no deletion command | Later |
| Real engines, adapters, exchange access, market data, credentials, trading, UI, LLM, Docker, cloud, server | Project 1 exclusions | — |

### 1.4 Named forward obligations

| Omission | Reason | Closed by |
|---|---|---|
| Foreign keys from `engine_runs.primary_terminal_diagnostic_id`, `command_invocations.primary_diagnostic_id`, `retry_decisions.primary_terminal_diagnostic_id` and `diagnostics.{experiment_id, run_id, invocation_id}` to their referents | `apply_command_semantic_outcome` (Stage 6) mints diagnostics inside the transaction whose run and invocation writes reference them and returns them to the caller afterwards, so an eager foreign key would refuse the operation itself; reconciliation diagnostics may lawfully describe identities that were never persisted. Stage 8 indexes the columns, ships `dangling_diagnostic_references()` (§4.6) and requires the integration test to record the returned diagnostics and prove zero dangling references at the end of every flow | Stage 9 (diagnostic increment), by a migration whose precondition query proves zero dangling references |
| `adapter_validation_results`, `sanitized_adapter_result_manifests` and the Stage 9 artifact, manifest, journal and audit tables | §1.3 | Stage 9 |
| `PROCESS.PID_REUSE_DETECTED` on a live `RUNNING` record | §1.3 | Stage 9 or a corrective plan |
| Adapter-authored diagnostics as `Diagnostic` rows | §1.3 | Stage 9 |
| The `finalization_deadline_utc` column and the `artifact_refs` foreign key of `stderr_artifact_id` | §1.3 | Stage 9 |
| The divergent-loser branch of `evaluate_retry` phase 3 (`RETRY.DECISION_CONFLICT`) under true concurrency | Over SQLite a transaction that read the decision key absent in phase 1 cannot see a concurrently committed row in phase 3 (WAL snapshot); its insert is refused, `run_operation` reruns, and phase 1 of the rerun replays the durable winner by identity without a projection comparison — the behaviour `retry.py`'s own docstring names ("the reload replays whatever durable row now exists … never a `RETRY.DECISION_CONFLICT` from a stale snapshot"). The branch stays exercised only by the in-memory hook case; the durable row is authoritative (Stage 5 plan 8.4). Recorded as declared behaviour (reading 19, §5.1 C-7), not a defect | Revisited only if a later stage changes `evaluate_retry` |
| Persisting the minted diagnostics of `apply_command_semantic_outcome` inside the operation | The operation's signature and transaction are Stage 6's; Stage 8 documents the caller obligation (record `reconciliation.diagnostics` immediately after a `Success`) and exercises it in Task 7 | Stage 10 composition, or Stage 9 if it widens the operation |
| `RuntimeAvailabilityObservation` minting after `describe`, the reconciliation lease, requeue of pre-launch attempts, the `db migrate` command | Composition and scheduling | Stage 10 |
| Spurious `PERSISTENCE.CONCURRENCY_CONFLICT` after two consecutive unrelated commits interleave a short write transaction (§5.1 case C-13) | Under the deferred-transaction model an unrelated commit between a transaction's first read and its first write refuses the write; `run_operation` reruns once, so two interleavings in a row return the conflict to the caller, who already treats it as a lost swap (the record stays a reconciliation target, never a false state). Recorded as a bounded residual with its measurement test, not hidden | Revisited only if Stage 10's scheduler measurements show it |

### 1.5 Carried notes and dispositions

Each note was located in the current source, tests or plans and its
applicability re-verified against the planning base; none is assumed open from
memory. Identifiers O-n refer to the planning inventory
(`.superpowers/sdd/stage8/inventory/inventory-carried-obligations.md`, ignored
evidence).

1. **`experiments/retry.py`, "Residual for Stage 8: a unit of work that
   surfaces a unique-key loss only at commit replays the durable row rather than
   conflicting" (O-1).** Still present at the base. Disposition: **RESOLVED AS
   DOCUMENTED BEHAVIOUR** — under §4.2 a unique-key loss surfaces at the
   `insert_if_absent` statement (as `inserted=False` with the stored winner when
   the row was committed before the transaction's snapshot, or as
   `PERSISTENCE.CONCURRENCY_CONFLICT` when it was committed after), never at
   `commit()`, so the commit-time shape the note describes cannot occur. The
   `LostSwap` path reruns once and phase 1 of the rerun replays the durable winner
   by identity, exactly as the note says; the divergent-loser
   `RETRY.DECISION_CONFLICT` branch is therefore unreachable by true concurrency
   over SQLite (reading 19, §5.1 cases C-7 and C-8). The docstring sentence is
   left unchanged (Stage 8 edits no `experiments` module); Task 8's guide records
   the reading.
2. **Stage 6 plan §1.4, "Causal-projection insert-loss residual — assigned to
   Stage 8 by the Stage 5 review; not absorbed" (O-2).** No tracked document
   defines the phrase; the Stage 5 ledger is not in this worktree. Declared
   reading: it names the same defect as note 1 (the `retry_decision_semantic_projection`
   comparison that an insert loss skipped), not `resolve_causal_closure`, whose
   missing-reference path fails closed to a durable `DENIED` row today.
   Disposition: **RESOLVED WITH NOTE 1** (the same reading); if a recovered
   definition differs, the row is re-opened before Stage 8 implementation begins.
3. **`supervision_lifecycle.py`, "a snapshot-isolated reader (the in-memory
   double today, Stage 8's later) cannot see a diagnostic seeded inside it"
   (O-3).** Disposition: **OWNED BY TASK 3** — `SqliteDiagnosticRecorder.record`
   commits in its own transaction before the operation's `begin()`; a diagnostic
   recorded for a swap that is then refused stays durable with no referencing
   record, which is permitted and tested.
4. **Stage 7 plan §1.4, `DiagnosticRecorder` and `ReconciliationSource`
   persistence "over the tables and the `(state, deadline_utc)` index" (O-4).**
   Disposition: **OWNED BY TASKS 3 AND 5**. The reconciler evaluates
   `past_deadline` in memory from `record.deadline_utc`; the `(state, deadline_utc)`
   index is created because spec 23.3.1 requires it, and the listing query is
   served by the `(state, cleanup_complete, created_at_utc, invocation_id)` index
   of §3.3.
5. **Stage 7 plan §1.4, live-record `PID_REUSE_DETECTED` write (O-5).**
   Disposition: **RE-DEFERRED** (§1.3, §1.4); Task 8's guard proves no
   persistence module writes `diagnostic_ids` on a non-terminal record outside
   the mapped compare-and-swap.
6. **Stage 6 plan matrix D, `RunEvent` "Stage 8 persists (`run_events`)" (O-6).**
   Disposition: **OWNED BY TASK 4** with the contract cases §7.2 adds.
7. **Stage 6 plan §1.4 and matrix D, sanitized manifests, validation results,
   `NegotiationResult`, `ExperimentAggregationResult` (O-7).** Disposition:
   **RULED STAGE 9** for the two tables (§1.3), **NO TABLE** for the other two
   (spec 23.3.1 names none). The matrix D cell is overridden by this plan's
   reading of the roadmap permission columns; the user is asked to confirm the
   ruling in the planning report.
8. **Adapter-authored diagnostics (O-8).** Disposition: **RE-DEFERRED** (§1.3).
9. **Port contract suite re-pointing (O-9).** Disposition: **OWNED BY TASK 4**
   with the per-case disposition table of §7.1; the two interleaving cases that
   require two simultaneously open writers are re-pinned as in-memory-only and
   replaced by serialized-writer cases over SQLite.
10. **Stage 3 plan, dataset repositories and registry relationship facts
    "deferred to Stage 8 persistence" (O-10).** Disposition: **OWNED BY TASKS 2
    AND 3**; `DatasetRepository` is released from `_DEFERRED_DEFINITIONS` in
    Task 3 (§2.6).
11. **Stage 5 plan §1.4, persisting diagnostics and audit events (O-11).**
    Disposition: diagnostics **OWNED BY TASK 3**; audit **MOOT FOR STAGE 8**
    (`AuditSink` and `AuditEvent` stay deferred to Stage 9).
12. **`InMemoryUnitOfWork` declared limitation, "commit validates the rows the
    transaction changed, not rows it merely read; Stage 8's SQLite writer
    serialisation makes the read-only interleaving unconstructible" (O-12).**
    Disposition: **CLOSED BY DESIGN** — §4.2's snapshot rule refuses any write
    after an unrelated commit, so a transaction's whole read set is protected
    from its first read to its commit (§5.1 case C-12 is the measurement).
13. **Every closed-world guard that proves Stage 8 absence (O-13).**
    Disposition: **OWNED BY TASK 1 AND TASK 8** exactly as §2.6 tabulates.
14. **`RuntimeAvailabilityObservationReader` over a table nothing writes until
    Stage 10 (O-14).** Disposition: **OWNED BY TASK 3** — the persistence-owned
    writer is not a port member, so the closed port inventory is untouched.

### 1.6 Escalations and declared readings the user must confirm

1. **Configuration snapshot — closed within Stage 8 (reading 22).** Spec 23.3.1
   asks the `experiments` row to own the "complete normalized material
   configuration snapshot, configuration hash, spec hash"; spec 22.2 says the
   configuration is "validated once, normalized to canonical JSON, hashed, and
   snapshotted for every queued experiment". Earlier drafts of this plan read the
   requirement as unmet because no canonical *experiment* record carries the
   snapshot; the committed source does carry it as its own typed record:
   `crypto_lab.configuration.snapshot.ConfigSnapshot`, produced by
   `snapshot_configuration(config)` from the resolved `ApplicationConfig`, holding
   the complete normalized configuration as canonical JSON plus both hashes
   (`CONFIGURATION_AUDIT_V1`, `CONFIGURATION_MATERIAL_BASE_V1`) and re-deriving
   both on validation. Closure: the `experiments` row gains the four columns
   `configuration_snapshot_schema_version`, `configuration_snapshot_json`,
   `configuration_audit_hash` and `material_base_configuration_hash` — one per
   field of the record (§3.3.1) — written only by the
   persistence-owned `SqliteConfigurationSnapshotWriter.freeze` (§4.4; the
   Stage 5 `ExperimentRepository` port is unchanged), required by repository
   guard and trigger for the `VALIDATED → QUEUED` swap, checked there for
   agreement with the frozen spec (`experiment_configuration_hash(spec,
   material_base_configuration_hash) == spec.configuration_hash` and
   `retry_policy_from_config(...) == spec.retry_policy`), immutable from `QUEUED`
   onward, and rebuilt on egress as a `ConfigSnapshot` whose validator re-checks
   the bytes (§4.3.1, §3.4). Classification: not (i), not (ii) — the
   requirement is met as written; the one honest residue is (iii)-shaped and
   bounded: the *producer* (loading a configuration file and calling the writer
   before `queue_experiment`) is composition, so Stage 10 owns the call and
   Stage 8 exercises it with the explicit test configurations of §7.1.1
   (`retrying_config()` in Task 7, whose flow must reach a successor;
   `ApplicationConfig()` in C-32 and in Task 7's negative control, whose
   default retry policy denies every retry) (§1.3). Spec 19.1
   also lists "strategy and configuration snapshots" among artifact classes with
   `EXPERIMENT`-owned configuration snapshots in its owner list; that artifact
   modelling is Stage 9's finalization path and is a second, derived
   representation of the same bytes — the row column of 23.3.1 is the authority
   Stage 8 implements, and Stage 9's artifact, if produced, must carry the same
   `configuration_audit_hash`. No canonical contract or boundary outside Stage 8
   changes.
2. **Diagnostic causal edges — closed within Stage 8 (reading 23); mixed
   classification, both parts met.** Spec 23.3.1 (`diagnostics` row): "causal
   edges live in a separate restricted join table". Stage 8 ships both
   representations with one writer: the record's `causal_diagnostic_ids` column
   (E8) remains the canonical reconstruction source — (i), a faithful physical
   representation of the record's own field, sorted, bounded, self-cause-free —
   and the separate relation `diagnostic_causes` (§3.3.9) carries every edge
   whose two endpoints are recorded, with both keys `RESTRICT`, so the relational
   property the earlier draft called unpreserved (a cause exists as a
   `diagnostics` row and cannot be deleted while referenced) now holds — the
   part that was (iii) in the earlier draft is implemented, not waived. The
   Stage 7 recording order (a primary recorded before the additionals it cites,
   each in its own autonomous transaction) is served without change: recording a
   diagnostic inserts the edges to its already-recorded causes *and* the edges
   from already-recorded referrers that cite it, so after any `_record_all`
   batch the relation equals the JSON edge set over recorded rows.
   `consistency_report().causal_edge_mismatches` measures exactly that equality
   and every recorder test and integration flow asserts it zero;
   `unresolved_causal_references` counts JSON causes that no row records yet
   (non-zero only between the statements of an interrupted batch, which the
   lifecycle reports as the recorder's `Failure`). There are not two writable
   authorities: only `SqliteDiagnosticRecorder.record` writes the relation,
   deriving it from the stored JSON with `json_each` inside the diagnostic's own
   transaction; a refused edge insert rolls the diagnostic back with it.
   `resolve_causal_closure` still reads the record, never the relation. No
   change to `experiments/supervision_lifecycle.py` or any Stage 5–7 contract.
   Roadmap reading: the relation is a Stage 8 mapping of the existing Stage 5
   field `Diagnostic.causal_diagnostic_ids` under the Stage 8 permission
   ("lifecycle state … mappings"; spec 23.3.1 places the join table in the
   `diagnostics` row's own table map), while Stage 9's "diagnostic causal
   chains" deliverable and its "diagnostic … increments" permission cover the
   causal-chain queries, the provenance layer over them and the
   diagnostic-reference foreign keys of §1.4 row 1 — none of which Stage 8
   ships (the same kind of permission reading as item 5's base registries).
3. **Diagnostic reference foreign keys** (§1.4 row 1): a deviation from spec
   23.3.1's "restricted references" for the same recording-order reason, with
   Stage 9 named as the closing owner and the dangling-reference query as the
   Stage 8 control.
4. **Stage 9 ownership of `adapter_validation_results` and
   `sanitized_adapter_result_manifests`** (§1.5 note 7).
5. **Base registries in Stage 8** (§1.2): the roadmap's permission names "base
   registries" and no later stage may add tables; the Stage 3 plan deferred
   dataset repositories to Stage 8. The alternative (leaving them out) would
   require a roadmap amendment before Stage 9 could reference a dataset or
   strategy owner.
6. **"Base artifact lifecycle mappings"** (roadmap Stage 8 deliverables) is read
   as the `artifact_owners` registry of §3.3.12 — the only artifact-lifecycle
   record that exists at the base (`CandidateArtifact`, `CandidateArtifactState`,
   `ArtifactRef` are Stage 9 canonical additions and stay deferred). Reading 20.
7. **`StrategyVersionRepository` and the two `register` extensions are
   plan-introduced application ports** under the "base registries" permission;
   spec 8.2 names only `DatasetRepository.get_by_hash`/`list_partitions`. They
   are new interfaces, not consumed ones (reading 12).
8. **Slot identity is experiment-scoped** (reading 7): spec 17.2 and 23.3 state
   the three-field attempt identity `(experiment_id, logical_slot_id,
   attempt_number)`; two 23.3.1 rows abbreviate it — the `engine_runs` row to
   `(logical_slot_id, attempt_number)` and the `engine_slots` row's identity cell
   to "`logical_slot_id`; owned by one experiment". The plan implements the three-field
   identity with `engine_slots` keyed `(experiment_id, logical_slot_id)` and no
   unscoped index; the wording discrepancy in the specification is recorded, not
   resolved by this plan.
9. **Two Stage 1 surfaces contradict the roadmap and are amended in Task 1:**
   `tests/safety/test_project_dependencies.py::_PROHIBITED_FAMILIES` lists
   `sqlalchemy` and `alembic`, and `docs/development/verification.md`
   ("Dependency changes") says no dependency operation may install a "database
   stack". Both predate the roadmap's Stage 8 authorization (spec 9 names
   SQLAlchemy 2.x and Alembic as approved technology decisions); the plan removes
   the two families and rewords the sentence to name the Stage 8 exception.

---

## 2. Authority, consumed interfaces, readings and reconciliation

### 2.1 Authority order

1. `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md` (the
   Stage 8 sections named in the header); a conflict between this plan and the
   specification is resolved for the specification, and every deviation this plan
   takes is listed in §1.4 and §1.6 with its reason and closing owner.
2. `docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md`, Stage 8 row
   (goal, deliverables, exclusions, test categories, exit evidence, permission
   columns) and the Stage 9 and Stage 10 rows as the far boundary.
3. The committed source at the planning base as evidence of the existing
   interfaces (never as permission to change the architecture): the ports of
   §2.2, the records of §3.1, the operations of §4.1, the doubles of §7.1.
4. `AGENTS.md`, `docs/development/verification.md`, `README.md` and ADR 0001
   (GitNexus stays `DISABLED_WITH_EVIDENCE`; the manual source, reference and
   diff workflow is the recorded fallback).

### 2.2 Consumed interfaces (existing, verified at the base)

Every signature below is copied from the committed module; Stage 8 implements
each one structurally and widens none.

<!-- consumed -->
| Symbol | Module | Exact contract Stage 8 must honour |
|---|---|---|
| `ExperimentRepository` | `crypto_lab.experiments.ports` | `get(experiment_id) -> Result[ExperimentRecord]`; `add(record) -> Result[None]`; `compare_and_swap(expected_revision, replacement) -> Result[ExperimentRecord]` |
| `EngineRunRepository` | `crypto_lab.experiments.ports` | `get`, `add_attempt(record) -> Result[None]`, `compare_and_swap`, `count_attempts(experiment_id, logical_slot_id) -> Result[int]`, `latest_attempt(...) -> Result[EngineRunRecord \| MISSING]`, `get_by_attempt_number(..., attempt_number) -> Result[EngineRunRecord \| MISSING]`, `append_event(event) -> Result[RunEvent]`, `list_events(invocation_id) -> Result[tuple[RunEvent, ...]]` |
| `CommandInvocationRepository` | `crypto_lab.adapters.ports` | `get`, `add`, `compare_and_swap`, `list_for_run(run_id, command_kind) -> Result[tuple[CommandInvocationRecord, ...]]` ordered `(created_at_utc, invocation_id)` |
| `RetryDecisionRepository`, `RetryDecisionInsertOutcome` | `crypto_lab.experiments.ports` | `get_by_predecessor(logical_slot_id, predecessor_run_id) -> Result[RetryDecisionRecord]`; `insert_if_absent(record) -> Result[RetryDecisionInsertOutcome]` with `inserted: bool` and `record` the durable winner |
| `RuntimeAvailabilityObservationReader` | `crypto_lab.experiments.ports` | `get(observation_id)`; `list_for_adapter(adapter_name, adapter_version, executable_hash)` sorted by `availability_observation_id`, unbounded |
| `DiagnosticReader` | `crypto_lab.experiments.ports` | `get(diagnostic_id)`; `get_many(diagnostic_ids)` sorted by `diagnostic_id`, unique identifiers, at most 256, any missing one a `Failure` |
| `UnitOfWork` | `crypto_lab.experiments.ports` | properties `experiments`, `engine_runs`, `command_invocations`, `retry_decisions`, `availability_observations`, `diagnostics`; `begin() -> UnitOfWork`; `commit() -> Result[None]`; `rollback() -> None` |
| `DiagnosticRecorder` | `crypto_lab.experiments.supervision_lifecycle` | `record(diagnostic) -> Result[None]`, idempotent on `diagnostic_id`, first instance kept |
| `ReconciliationSource` | `crypto_lab.process_supervision.ports` | `list_reconciliation_targets() -> Result[tuple[CommandInvocationRecord, ...]]` (every nonterminal invocation and every terminal one with `cleanup_complete=false`, ordered `(created_at_utc, invocation_id)`); `run_facts(run_id) -> Result[RunReconciliationFacts]` |
| `RunReconciliationFacts` | `crypto_lab.process_supervision.models` | the seven-field record `run_facts` returns (`run_id`, `experiment_id`, `run_state`, `run_revision`, `attempt_token_hash`, `request_hash`, `experiment_state`) |
| `Clock` | `crypto_lab.domain.ports` | `now_utc()`; used by persistence only to stamp its own `Failure` diagnostics |
| `Result`, `Success`, `Failure` | `crypto_lab.domain.results` | every port method returns one; a `Failure` carries exactly one diagnostic when persistence mints it |
| `CONCURRENCY_CONFLICT`, `INVARIANT_VIOLATION`, `STAGE5_DIAGNOSTIC_CODES` | `crypto_lab.experiments.diagnostics` | **referenced by test only**: the two codes a repository may mint today are respelled as literals in `persistence/diagnostics.py` and a Task 1 test pins the literals equal to these constants (persistence does not import this module; the closed six-entry table is why Stage 8's additional codes live in their own table, reading 9); `stage5_failure` is not consumed — persistence mints its failures through `persistence_failure` |
| `CanonicalModel` | `crypto_lab.domain.base` | strict frozen models (`extra="forbid"`, `frozen=True`, `strict=True`) |
| `canonical_json_bytes`, `canonical_json_text` | `crypto_lab.domain.canonical_json` | the canonical serializer used for every JSON snapshot column and every egress payload |
| `format_utc`, `parse_utc`, `UtcDateTime`, `CalendarValidUtcDateTime` | `crypto_lab.domain.time` | the only timestamp renderers; egress text is regenerated through them |
| `format_decimal`, `CanonicalDecimal` | `crypto_lab.domain.financial` | canonical decimal text (max 256 characters) |
| `Sha256`, the prefixed identifier aliases | `crypto_lab.domain.identifiers` | 64 lowercase hex; `exp_`/`run_`/`inv_`/`evt_`/`slot_`/`diag_`/`avail_`/`ds_`/`part_`/`strv_`/`strat_` prefixes with UUID4 suffixes |
| `ExperimentRecord`, `ExperimentSpec`, `SelectedEngineSlot`, `SlotCompatibility`, `experiment_spec_hash` | `crypto_lab.domain.experiment` | §3.1 |
| `EngineRunRecord`, `AdapterIdentity`, `EngineIdentity` | `crypto_lab.domain.engine_run` | §3.1 |
| `CommandInvocationRecord`, `ProcessIdentity`, `NativeExitValue` | `crypto_lab.domain.command_invocation` | §3.1 |
| `RetryDecisionRecord`, `RetryPolicy`, `retry_decision_semantic_projection` | `crypto_lab.domain.retry` | §3.1 |
| `RunEvent`, `InvocationEventLedger` | `crypto_lab.adapters.events` | §3.1; the ledger is the contiguity authority (reading 14) |
| `RuntimeAvailabilityObservation` | `crypto_lab.domain.descriptors` | §3.1 |
| `Diagnostic`, `DiagnosticCategory`, `DiagnosticSeverity`, `ErrorCode` | `crypto_lab.domain.diagnostics` | §3.1; `ErrorCode` is an open pattern (`^[A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)+$`) |
| `ArtifactOwnerRef`, `ARTIFACT_OWNER_ADAPTER`, `artifact_owner_hash`, `owner_presentation` | `crypto_lab.artifacts.ownership` | §3.1 |
| `StrategyVersion`, `StrategySourceProvenance` | `crypto_lab.strategy.versioning` | §3.1 |
| `DatasetDescriptor`, `DatasetPartition`, `validate_dataset_identity` | `crypto_lab.datasets` | §3.1 |
| `ExperimentState`, `EngineRunState`, `CommandInvocationState`, `CommandKind`, `ProcessExitCategory`, `RetryTerminalState`, `TERMINAL_*` sets, `process_exit_category_for` | `crypto_lab.domain.lifecycle` | the closed enumerations every CHECK constraint enumerates (§3.3) |
| `DatabaseConfig`, `PathsConfig` | `crypto_lab.configuration.models` | `filename: SafeFilename = "crypto_lab.sqlite3"`, `busy_timeout_ms: int` in `100..60000` default `5000`; `paths.runtime_root` |
| `ConfigSnapshot`, `snapshot_configuration`, `material_base_configuration_hash` | `crypto_lab.configuration.snapshot` | the frozen configuration snapshot record (`schema_version`, `configuration_json`, `configuration_audit_hash`, `material_base_configuration_hash`) and its producer; reading 22 |
| `experiment_configuration_hash`, `assert_queue_freeze` | `crypto_lab.domain.experiment` | the hash the freeze guard recomputes and the Stage 5 kernel whose two equalities it mirrors (reading 22) |
| `retry_policy_from_config` | `crypto_lab.configuration.retry_policy` | the projection the freeze guard compares against `spec.retry_policy` |
| `run_operation`, `LostSwap` | `crypto_lab.experiments.experiment_service` | the reload-once driver every request-driven operation runs under; consumed unchanged by Task 7 (the seventeen operations and their reads, writes and failure codes are the matrix of §4.1) |
| `Stage5InvocationLifecycle` | `crypto_lab.experiments.supervision_lifecycle` | the nine-member lifecycle the supervisor drives; consumed unchanged by Tasks 5 and 7 |
| `reconcile_invocations` | `crypto_lab.process_supervision.reconciliation` | the restart reconciler; consumed unchanged by Task 5 |
| `WindowsProcessSupervisor` | `crypto_lab.process_supervision.supervisor` | the production supervisor; consumed unchanged by Task 7 |
| `InMemoryBackingStore`, `InMemoryUnitOfWork`, `sample_*` builders, `FixedClock`, `SequentialIdentitySource` | `tests/doubles/experiments.py` | the in-memory side of the parametrized contract suite and the fixture builders every SQLite test reuses |
| `PortHarness`, `harness` | `tests/unit/experiments/test_port_contracts.py` | the factory fixture Task 4 re-points (§7.1) |
<!-- /consumed -->

### 2.3 Placement decisions

| Concern | Placement | Why |
|---|---|---|
| Database engine, PRAGMA policy, connection lifetime, error classification, path composition, startup checks | `src/crypto_lab/persistence/database.py` | spec 27.2 names `persistence/database.py`; one module owns every DBAPI-level fact |
| Stage 8 diagnostic codes and the `Failure` factory | `src/crypto_lab/persistence/diagnostics.py` | Stage 7 precedent (`process_supervision/diagnostics.py`); the Stage 5 code table is closed by test |
| Declarative table metadata, CHECK/index/trigger definitions | `src/crypto_lab/persistence/schema.py` | spec 27.2 `persistence/mappings.py`; one source for Alembic drift comparison and the repositories |
| Row codecs (ingress projection, egress rebuild) | `src/crypto_lab/persistence/codecs.py` | pure functions over records and plain values; no SQLAlchemy import, so the codec round-trip properties run without a database |
| Unit of work and transaction | `src/crypto_lab/persistence/unit_of_work.py` | spec 27.2 `persistence/unit_of_work.py` |
| The four lifecycle repositories and the `engine_slots` projection | `src/crypto_lab/persistence/repositories.py` | spec 27.2 `persistence/repositories.py`; all four are bound to one transaction and share the CAS statement shape |
| Diagnostic reader/recorder, observation reader/writer, strategy-version and dataset repositories, artifact-owner registry | `src/crypto_lab/persistence/registries.py` | insert-only tables with autonomous or transaction-bound access; separated so the Stage 5 reader-census guard names one class |
| `ReconciliationSource` implementation | `src/crypto_lab/persistence/reconciliation_source.py` | spec 27.1 "persistence recovery"; a read-only session distinct from the unit of work |
| Alembic script directory | `src/crypto_lab/persistence/migrations/` (`__init__.py`, `env.py`, `script.py.mako`, `versions/__init__.py`, `versions/r0001_stage8_baseline.py`) | packaged with the wheel by the pinned hatch configuration; no root `alembic.ini` (the sdist include list and the Stage 7 shape scan forbid one) |
| Migration runner and revision checks | `src/crypto_lab/persistence/migration_runner.py` | programmatic Alembic; the only module that imports `alembic.command`/`alembic.config`/`alembic.script`/`alembic.runtime` |
| Registry ports | `src/crypto_lab/datasets/ports.py` (`DatasetRepository`), `src/crypto_lab/strategy/ports.py` (`StrategyVersionRepository`) | spec 8.1 places `DatasetRepository` in `datasets`; spec 27.1 lists "repository ports" under `datasets`; the strategy registry has no spec interface and follows the same pattern in its owning package |
| Migration consistency script | `scripts/verify_migrations.py` | Stage 3 precedent (`scripts/generate_schemas.py`); invoked by the new launcher profile with fixed `-I -B` argv |
| SQLite test support (harness, fixtures, two-connection helpers) | `tests/persistence_support/__init__.py`, `tests/persistence_support/harness.py` | `tests/doubles` may not name SQLAlchemy (its text is pinned) and `tests/contract` is the adapter harness; `from persistence_support.harness import ...` follows the existing `from doubles.experiments import ...` style |
| Tests | `tests/unit/persistence/*.py`, `tests/integration/persistence/*.py`, `tests/property/test_persistence_codecs.py`, `tests/safety/test_stage8_boundaries.py` | one basename each, unique across `tests/`; names avoid nothing (the Stage 7 shape scan is retired in Task 1) |

### 2.4 Frozen-byte and contract constraints

- The 35 registered schemas, their `$id`s and digests are unchanged; no model is
  edited, so `schema-generate-check` stays clean in every task.
- `experiments/ports.py`, `adapters/ports.py`, `process_supervision/ports.py`,
  `experiments/supervision_lifecycle.py` and `domain/ports.py` are not edited; the
  member-set pins of `test_port_contracts.py`, `test_domain_ports.py`,
  `test_supervision_ports.py` and `test_supervision_lifecycle.py` hold unchanged.
- No `experiments`, `adapters`, `process_supervision`, `domain`, `capabilities`
  or `configuration` module is edited (the Stage 7 guard pins the file counts of
  the first two packages at 12 and 11).
- `tests/doubles/experiments.py` and `tests/doubles/supervision.py` are not
  edited; the SQLite side of every parametrized suite lives in
  `tests/persistence_support/`.
- The lifecycle transition tables, the retry gates, the aggregation classifier,
  the event ledger and the hashing profiles are referenced, never restated.

### 2.5 Declared readings of the specification

Each reading is cited by number from the sections and tasks that rely on it.

1. **"SQLAlchemy 2.x provides explicit mapped persistence models and session
   boundaries" (spec 23.2).** Mapped persistence models are the declarative
   `MetaData` classes of `schema.py`; the session boundary is the unit of work's
   exclusively owned `Connection` and its one transaction. Statements are
   SQLAlchemy Core (`insert`, `update`, `select`) executed on that connection. No
   ORM `Session` or identity map is used: egress must re-validate every row into a
   fresh canonical record (spec 23.2 "validates on both ingress and egress"), and
   an identity map would hand back Python objects that bypass that step.
2. **`begin()` returns the active transaction (spec 8.2).** `SqliteUnitOfWork`
   is the root; `begin()` returns a `SqliteTransaction` that also satisfies
   `UnitOfWork` structurally (the contract suite asserts `isinstance(transaction,
   UnitOfWork)`). `begin()` on a transaction, `commit()` twice, and repository
   access on the root or on a closed transaction raise `RuntimeError` (programmer
   defects, spec 8.2). `rollback()` is idempotent and a no-op after `commit()`.
3. **Transaction and conflict model (spec 23.1–23.2, 21.2.1).** `begin()` issues
   an explicit deferred `BEGIN` on the owned connection (the DBAPI's implicit
   transaction management is disabled). Reads establish one WAL snapshot; the
   first write takes the writer lock. The DBAPI conditions "database is locked"
   after the busy timeout (`SQLITE_BUSY`), a refused snapshot upgrade
   (`SQLITE_BUSY_SNAPSHOT`), and a unique or primary-key violation
   (`SQLITE_CONSTRAINT_UNIQUE`, `SQLITE_CONSTRAINT_PRIMARYKEY`) are each returned
   by the repository call that hit them as a `Failure` carrying
   `PERSISTENCE.CONCURRENCY_CONFLICT`. A refused statement is aborted by SQLite
   while the transaction stays open and usable (`ON CONFLICT ABORT` semantics),
   exactly as the in-memory double behaves and as the shared contract cases
   require (a refused `add` followed by reads, further writes and a successful
   `commit()`); a later write after a stale-snapshot refusal fails again on its
   own. The application never continues after a write `Failure` anyway
   (`run_operation` rolls back and reruns; the lifecycle returns it). A
   foreign-key, CHECK or trigger violation (`SQLITE_CONSTRAINT_FOREIGNKEY`,
   `SQLITE_CONSTRAINT_CHECK`, `SQLITE_CONSTRAINT_TRIGGER`) is
   `CORE.INVARIANT_VIOLATION` — the caller wrote an impossible aggregate state —
   with the same statement-level scope. Only the I/O class (`SQLITE_FULL`,
   `SQLITE_IOERR_*`, `SQLITE_NOMEM`, `SQLITE_READONLY_*`) closes the transaction,
   because SQLite may have rolled it back itself; the transaction then answers
   every later call and `commit()` with the stored `PERSISTENCE.WRITE_FAILED`, and
   `rollback()` consults the DBAPI connection's `in_transaction` before issuing
   `ROLLBACK`. The three repository methods that issue more than one statement
   (`ExperimentRepository.add`, `ExperimentRepository.compare_and_swap` when it
   rewrites the slot projection, `SqliteDatasetRepository.register`) run their
   statements inside one `SAVEPOINT` (`Connection.begin_nested()`): a refusal of
   any later statement rolls back to that savepoint before the method returns
   its `Failure`, so a failed repository mutation leaves nothing of itself
   staged and cannot later be committed partially, even by a caller that ignores
   the `Failure` (§4.2, §5.1 C-29). Single-statement methods need no savepoint
   (the statement's own abort is the boundary). Over SQLite `commit()` therefore never returns
   `PERSISTENCE.CONCURRENCY_CONFLICT`; the port docstring says "may", and its two
   consumers (`run_operation`, `Stage5InvocationLifecycle.append_event`) handle
   any `Failure` uniformly. Consequences recorded in §1.5 notes 1 and 12 and
   measured in §5.
4. **A missing identity is `CORE.INVARIANT_VIOLATION`** (port docstring); the
   message contains the phrase `does not exist` (pinned by
   `test_supervision_lifecycle.py`). Every diagnostic of such a `Failure` carries
   that code, because `retry.py` and `aggregation.py` classify an all-invariant
   failure as absence; a genuine read fault therefore never uses that code.
5. **Compare-and-swap refusal precedence (authoritative text in §4.3.1).**
   Every compare-and-swap first reads the stored row inside the current
   transaction (the connection's own view, including its earlier writes); a
   missing row is `PERSISTENCE.CONCURRENCY_CONFLICT`; a stored revision different
   from `expected_revision` is `PERSISTENCE.CONCURRENCY_CONFLICT`; only then is a
   replacement whose `revision != expected_revision + 1` refused with
   `CORE.INVARIANT_VIOLATION` (the double's "persistence CHECK analogue"); the
   conditional `UPDATE … WHERE <identity> = ? AND revision = ?` follows, and zero
   affected rows — or the write-promotion refusal of reading 3, which yields no
   rowcount — is `PERSISTENCE.CONCURRENCY_CONFLICT` (spec 23.2). The three
   refusals perform no mutation; the order is exactly the double's
   `_compare_and_swap` and is what `test_compare_and_swap_rejects_a_missing_row_and_a_wrong_revision_step`
   and `test_a_failed_second_write_leaves_the_first_undurable_after_rollback`
   require.
6. **Timestamps are typed columns (spec 23.3.1).** Every timestamp column is
   `INTEGER` microseconds since `1970-01-01T00:00:00Z`, computed with exact
   integer arithmetic on `datetime` values (never `timestamp()` floats) and
   rendered back through `format_utc` after `datetime.fromtimestamp`-free
   reconstruction (`EPOCH + timedelta(microseconds=n)`), so lexical order of the
   canonical text (20 or 27 characters) never matters and `deadline_utc ==
   launch_attempted_at_utc + timeout_seconds` is a CHECK in integer arithmetic.
7. **Slot identity is scoped by its owning experiment.** The specification
   states the attempt identity in two forms that are not identical: sections
   17.2 ("idempotent on `(experiment_id, logical_slot_id, attempt_number)`") and
   23.3 ("unique `(experiment_id, logical_slot_id, attempt_number)`") give the
   three-field identity, while the 23.3.1 `engine_runs` row abbreviates it to
   "Unique `(logical_slot_id, attempt_number)`" and the 23.3.1 `engine_slots`
   row states the identity cell as "`logical_slot_id`; owned by one experiment".
   This plan implements the three-field identity and treats both shorter table
   wordings as abbreviations of an experiment-owned identifier, not as a global
   key: `logical_slot_id` is unique **within** its
   experiment (`ExperimentSpec._validate_selected_engine_slots` requires unique
   slot identifiers per spec, nothing requires them unique across experiments,
   and the shared fixtures give every experiment the same `SLOT_A`/`SLOT_B`), so
   `engine_slots` has `PRIMARY KEY (experiment_id, logical_slot_id)`,
   `engine_runs` keeps `run_id` as its primary identity with the port's
   `UNIQUE (experiment_id, logical_slot_id, attempt_number)` and the composite
   foreign key `(experiment_id, logical_slot_id) → engine_slots`, and no
   unscoped `(logical_slot_id, attempt_number)` index exists. Every slot lookup
   carries its experiment scope from a port argument or a stored record (§4.3
   "experiment scope" table). The discrepancy between the two source statements
   is recorded here and in §1.6 item 8; it is not presented as already
   resolved in the specification text.
8. **`artifact_owners` identity is `owner_hash`** (`artifact_owner_hash`, profile
   `ARTIFACT_OWNER_V1`); the specification's `artifact_owner_id` has no identifier
   type in the domain and minting one would be a canonical decision, so the hash is
   the primary key. Stage 9 may add a surrogate column.
9. **New codes within the `PERSISTENCE` category (spec 21.2: "more specific codes
   may be added within a category").** `persistence/diagnostics.py` defines the
   closed table `STAGE8_DIAGNOSTIC_CODES` with postures: `PERSISTENCE.CONCURRENCY_CONFLICT`
   (retriable after reload), `PERSISTENCE.WRITE_FAILED` (spec 21.2.1;
   disk-full, read-only, I/O; not automatically retriable),
   `PERSISTENCE.MIGRATION_MISMATCH` (spec 21.2 "migration mismatch"; the database
   revision is unknown, newer, or behind head when a current database is required;
   not retriable), `PERSISTENCE.STORAGE_UNAVAILABLE` (the file cannot be opened,
   a PRAGMA cannot be applied or read back, `quick_check` fails, or the
   `application_id` names a foreign database; not retriable), plus
   `CORE.INVARIANT_VIOLATION`. The two codes shared with Stage 5 are respelled
   literals (`persistence` may not import `experiments.diagnostics`) pinned equal
   to `experiments.diagnostics.CONCURRENCY_CONFLICT`/`INVARIANT_VIOLATION` by a
   Task 1 test, exactly as `process_supervision/diagnostics.py` does.
   `source_component` is `persistence`; every failure carries exactly one
   diagnostic stamped from the injected `Clock`.
10. **Egress validation runs in JSON mode.** The codec assembles a JSON-compatible
    payload (identifier and hash text, enum values, canonical decimal text, UTC
    text from `format_utc`, parsed JSON snapshot columns, absent keys for `NULL`
    `MISSING` columns) and validates it with the record's `model_validate_json`
    over `canonical_json_bytes(payload)`; strict Python mode would refuse the text
    forms. A validation error on egress is `CORE.INVARIANT_VIOLATION` with the
    table and identity in `details` (a corrupt row is an impossible aggregate state,
    never silently reinterpreted — spec 10.4).
11. **Writers that are not port members.** `SqliteAvailabilityObservationWriter.add`
    and `SqliteArtifactOwnerRegistry.register/get` are persistence-owned classes
    exposed on `SqliteUnitOfWork`/`SqliteTransaction` as extra attributes; the
    Stage 5 `UnitOfWork` protocol and its member-set pin are untouched (structural
    typing ignores extra members).
12. **Registry ports.** `DatasetRepository` (`datasets/ports.py`) carries spec 8.2's
    `get_by_hash(content_hash) -> Result[DatasetDescriptor]` and
    `list_partitions(dataset_id) -> Result[tuple[DatasetPartition, ...]]` plus the
    **plan-introduced** extension `register(descriptor, partitions) -> Result[None]`
    (idempotent on an identical content hash, spec 18.3 "an existing content hash
    is reused idempotently"). `StrategyVersionRepository` (`strategy/ports.py`) is
    a **plan-introduced** port (spec 8.2 names none for strategy versions; the
    table is spec 23.3.1's) carrying `get_by_hash(content_hash) -> Result[StrategyVersion]`
    and `register(version) -> Result[None]` (idempotent on an identical hash; a
    different record under the same hash is `CORE.INVARIANT_VIOLATION`; a second
    version of one strategy at the same `created_at_utc` — two valid records that
    collide on the spec-mandated `(strategy_id, created_at_utc)` index — is
    `CORE.INVARIANT_VIOLATION` when the pre-insert read within the transaction
    sees the earlier row; a colliding row committed by another connection after
    this transaction's snapshot surfaces instead as the write refusal of
    reading 3 (`PERSISTENCE.CONCURRENCY_CONFLICT`), whose rerun then reads it;
    Task 3's fixtures give every version of one strategy a distinct instant).
    Both are new interfaces under the "base registries" permission (§1.6
    item 7).
13. **"Immutable spec and retry-policy bytes after queueing" and "terminal records
    cannot transition" (spec 23.3, 16.1)** are enforced by the application
    (unchanged Stage 5 predicates), by the repository (the experiment CAS refuses a
    replacement whose `spec_hash` differs from the stored one when the stored state
    is at or after `QUEUED`), and by triggers (§3.4) that refuse a state change on a
    terminal row and a `spec` change at or after `QUEUED` at the SQL level.
14. **Run-event contiguity ("first accepted sequence is exactly 1, each later
    accepted sequence is prior plus one", spec 23.3.1)** is the classification of
    `InvocationEventLedger` (Stage 6), which alone decides acceptance; the table
    enforces the key `(invocation_id, sequence)`, `sequence` in `1..1000000`, the
    unique `event_id` and invocation-to-run agreement. Task 5 proves the
    composition keeps every stored ledger contiguous.
15. **Startup revision policy (spec 23.4, 29.2 step 2).** `check_revision` returns
    one of `EMPTY`, `CURRENT`, `BEHIND`, `UNKNOWN`, `UNVERSIONED` (§6.4). A normal
    command accepts only `CURRENT`; `apply_migrations` accepts `EMPTY` and
    `BEHIND`; `UNKNOWN` (a revision not in the script directory — an unsupported
    newer or foreign database) and `UNVERSIONED` (user tables without
    `alembic_version`) are refused with `PERSISTENCE.MIGRATION_MISMATCH` and no
    statement other than the reads is issued. Nothing ever drops, rebuilds or
    renames a database file.
16. **`env.py` is import-safe.** Alembic executes `env.py` when it runs a
    migration; the fresh-import probe of `tests/unit/test_package_layout.py`
    imports it as a plain module. The module runs migrations only when the Alembic
    proxy is established (attribute access on `alembic.context` outside a run
    raises, which the module catches to decide); this library behaviour is
    verified by Task 2's probe test before anything relies on it.
17. **`versions/__init__.py` exists and Alembic ignores it** (its revision-file
    filter excludes `__init__`); verified by Task 2's single-head test, which would
    otherwise fail to load the script directory.
18. **Deterministic revision identifiers.** Revision files are named
    `r0001_stage8_baseline.py` with `revision = "r0001_stage8_baseline"`,
    `down_revision = None`; later stages continue the `r000N_<stage>_<topic>`
    shape. Identifier-safe names keep every version module importable for the
    Stage 3 source-file guard, the layout probe and strict mypy.
19. **The divergent-loser retry conflict is unreachable by true concurrency
    over SQLite.** `evaluate_retry` compares semantic projections only when
    `insert_if_absent` returns `inserted=False` in the same attempt whose phase 1
    saw the key absent; under the WAL snapshot rule that attempt cannot see a row
    committed after its snapshot, its insert is refused (`LostSwap`), and the
    rerun's phase 1 replays the durable row by identity without a projection
    comparison (`retry.py`: "the reload replays whatever durable row now exists
    … never a `RETRY.DECISION_CONFLICT` from a stale snapshot"). A concurrent
    divergent loser therefore receives `Success(winner)` after exactly two
    `begin()` calls (§5.1 C-7); `RETRY.DECISION_CONFLICT` stays reachable only
    through the in-memory hook case. The durable row is authoritative (Stage 5
    plan 8.4); nothing in `experiments` changes.
20. **"Base artifact lifecycle mappings"** (roadmap Stage 8 deliverables)
    denotes the `artifact_owners` registry (§3.3.12), the only artifact-lifecycle
    record that exists at the base; every other artifact table is Stage 9's
    (§1.3, §1.6 item 6).
21. **Multi-statement repository failures roll back to a savepoint** (reading
    3, §4.3): the postcondition "a failed repository mutation cannot later be
    committed partially" is met inside the repository, not by trusting the
    caller; the transaction stays usable afterwards; the whole-unit-of-work
    rollback that `run_operation` performs on any `Failure` remains the
    operations' own second line. The savepoint is entered only after every
    read-only refusal of §4.3.1 has passed, so a refused replacement never opens
    one; because the repositories issue Core statements on the connection and
    hold no ORM session, there is no unit-of-work flush that could write a
    rejected replacement before validation or outside that boundary — every
    statement executes when issued and only where the method issues it.
22. **The frozen configuration snapshot is `ConfigSnapshot`** (spec 22.2
    "validated once, normalized to canonical JSON, hashed, and snapshotted for
    every queued experiment"; spec 23.3.1 `experiments` row). Its source is the
    existing `crypto_lab.configuration.snapshot.snapshot_configuration(config)`
    over the resolved `ApplicationConfig`; the record carries the complete
    normalized configuration as canonical JSON text (bounded by
    `MAX_CONFIGURATION_BYTES`), `configuration_audit_hash`
    (`CONFIGURATION_AUDIT_V1`) and `material_base_configuration_hash`
    (`CONFIGURATION_MATERIAL_BASE_V1`), and its own validator re-validates the
    JSON through `ApplicationConfig`, re-canonicalizes it and re-derives both
    hashes, so egress reconstruction is self-checking. No value is reconstructed
    from defaults and no hash substitutes for the data. Its relationship to the
    experiment: `experiment_configuration_hash(spec, snapshot.material_base_configuration_hash)
    == spec.configuration_hash` and `retry_policy_from_config(config.scheduler.retry)
    == spec.retry_policy` (the same two equalities `assert_queue_freeze` proves
    from the request's hash and derived policy). Persistence location and
    freeze rule: the four `experiments` columns of §3.3.1 (one per field of
    the record, the envelope `schema_version` included), written only by
    `SqliteConfigurationSnapshotWriter.freeze` (§4.4, the transaction member
    `configuration_snapshots`); that method is the Stage 8-owned typed ingress
    (a persistence-owned member; the Stage 5 `ExperimentRepository` port is
    unchanged), called by the composition root while the experiment is `DRAFT`
    or `VALIDATED` and before `queue_experiment`; the `VALIDATED → QUEUED` CAS is
    refused at the repository (§4.3.1 step d′) and by trigger
    (T-EXP-QUEUE-SNAPSHOT) when no consistent snapshot is frozen, and the frozen
    columns are immutable from `QUEUED` onward (T-EXP-SNAPSHOT-FROZEN). Rows that
    tests insert directly at or after `QUEUED` through `add` are scaffolding
    (production reaches `QUEUED` only through `queue_experiment`) and are
    counted by `consistency_report().queued_without_snapshot`, which every
    integration flow asserts to be zero.
23. **Causal edges live in `diagnostic_causes` and the record's JSON field
    stays the reconstruction source** (spec 23.3.1 "causal edges live in a
    separate restricted join table"). The relation's rows are written by exactly
    one writer, `SqliteDiagnosticRecorder`, derived from the recorded
    diagnostic's `causal_diagnostic_ids` (read through `model_dump`, never by
    attribute, so the Stage 5 traversal guard holds): recording `d` inserts the
    edges `(d, c)` for every cause `c` already recorded and the edges `(x, d)` for
    every already-recorded `x` whose causes name `d`, all inside `record`'s one
    transaction with the diagnostic row. Both foreign keys are `RESTRICT`, so an
    edge exists exactly when both endpoints exist; the Stage 7 referrer-first
    recording order is therefore served without change (the primary's edge to a
    later-recorded additional appears when the additional is recorded, inside the
    same `_record_all` batch). The record's `causal_diagnostic_ids` column is the
    canonical reconstruction source (a `Diagnostic` is rebuilt from its own
    fields); the relation is the restricted, queryable home of the same edges and
    never diverges from it: `consistency_report().causal_edge_mismatches` (JSON
    edges whose referent row exists but lack a relation row, or relation rows
    absent from the JSON) is zero after every recorded batch and after every
    integration flow. There are not two writable authorities: nothing writes the
    relation except the recorder deriving it from the record.

### 2.6 Closed-world guard reconciliation

The merged tree enforces closed sets by exact equality. Every guard Stage 8
trips is reconciled here, assigned to the task whose work first trips it, and
none is weakened, deleted or replaced by a lower bound (the one retirement, the
Stage 7 "Stage 8 has not started" test, is replaced by the Stage 8 guard's
positives). **This section is the single authority for every guard edit Stage 8
makes to a Stage 1–7 test file.** It was derived by enumerating every `assert`,
parametrize literal and module constant of the guard files
(`.superpowers/sdd/stage8/inventory/inventory-guards.md`, 100 rows: 20 trip, 37
depend on a design choice this plan fixes, 43 proven unaffected). The closures
of readings 22 and 23 add four columns, one table (`diagnostic_causes`, the
thirteenth), two triggers and one writer class, all inside modules this section
already counts (`schema.py`, the baseline revision, `registries.py`); they add
no source file, import root, dependency, deferred name, launcher operation or
verifier step, so every census value below is unchanged by them. They do widen
the Stage 8 boundary guard's import expectation for `crypto_lab.persistence`
by `crypto_lab.configuration.snapshot` and `crypto_lab.configuration.retry_policy`
(Task 8 pins the set).

**Rule.** A task that creates a module under `src/crypto_lab` appends that
module, in the same commit, to both `_ALLOWED_SOURCE_FILES` in
`tests/safety/test_stage3_boundaries.py` and `PACKAGE_MODULES` in
`tests/unit/test_package_layout.py`, and moves the two `len(...) == 95`
cross-pins in `tests/unit/process_supervision/test_supervisor_preflight.py` and
`tests/unit/process_supervision/test_restart_reconciliation.py` to the running
size. A task that first defines a deferred name removes exactly that name from
`_DEFERRED_DEFINITIONS`, its literal set and its count. A task that first imports
a root outside `_ALLOWED_IMPORT_ROOTS` adds exactly that root to the set, to the
literal set of `test_the_import_root_allowlist_is_exactly_the_reviewed_twenty_two`
and to its count (and to the `len(roots) == 27` cross-pin in
`test_supervisor_preflight.py`). A task whose persistence module imports an
infrastructure root adds exactly one `(module, root)` pair per module and root
to `_INFRASTRUCTURE_EXEMPTIONS` in `tests/safety/test_stage5_boundaries.py`.

**Source-file allowlist.** `_ALLOWED_SOURCE_FILES` is a literal set of 95 paths
at the planning base. Stage 8 adds exactly 15 paths, taking it to 110; the same
15 dotted names join `PACKAGE_MODULES` directly after `crypto_lab.persistence`
in the order below (the relative-order pins of the `process_supervision` entries
survive a uniform shift).

<!-- source-files -->
| Task | Paths appended (relative to `src/crypto_lab`) | Running size |
|---|---|---|
| 1 | `persistence/database.py`, `persistence/diagnostics.py` | 97 |
| 2 | `persistence/schema.py`, `persistence/migration_runner.py`, `persistence/migrations/__init__.py`, `persistence/migrations/env.py`, `persistence/migrations/versions/__init__.py`, `persistence/migrations/versions/r0001_stage8_baseline.py` | 103 |
| 3 | `persistence/codecs.py`, `persistence/registries.py`, `datasets/ports.py`, `strategy/ports.py` | 107 |
| 4 | `persistence/unit_of_work.py`, `persistence/repositories.py` | 109 |
| 5 | `persistence/reconciliation_source.py` | 110 |
<!-- /source-files -->

Every new module is import-side-effect free: the layout probe imports each in a
fresh interpreter with file, process and socket calls patched to raise, so no
engine is created, no file is opened, no `ScriptDirectory` is resolved and
nothing is written to the working directory at import time (`env.py` follows
reading 16; `schema.py` builds `MetaData` only; `database.py` binds the engine in
`SqliteDatabase.open`, never at import).

**Import-root allowlist.** `_ALLOWED_IMPORT_ROOTS` holds 27 roots. Task 1 adds
`sqlalchemy` (28) and Task 2 adds `alembic` (29); the test docstring arithmetic
gains a Stage 8 paragraph. No persistence module imports `sqlite3` (DBAPI error
codes are local `Final` integers read from the wrapped exception's
`sqlite_errorcode` attribute), `logging`, `os`, `sys`, `time`, `types`, `io`,
`shutil`, `tempfile`, `threading`, `queue`, `ctypes`, `asyncio` or `subprocess`.

<!-- import-roots -->
| Task | Root added | Confined to (Stage 8 guard, Task 8) | Running count |
|---|---|---|---|
| 1 | `sqlalchemy` | `persistence/database.py`, `persistence/schema.py`, `persistence/migration_runner.py`, `persistence/migrations/env.py`, `persistence/migrations/versions/r0001_stage8_baseline.py`, `persistence/registries.py`, `persistence/unit_of_work.py`, `persistence/repositories.py`, `persistence/reconciliation_source.py` | 28 |
| 2 | `alembic` | `persistence/migration_runner.py`, `persistence/migrations/env.py`, `persistence/migrations/versions/r0001_stage8_baseline.py` | 29 |
<!-- /import-roots -->

**Infrastructure-root exemptions (Stage 5 guard).** `_INFRASTRUCTURE_ROOTS`
denies `sqlalchemy`, `sqlite3`, `alembic`, `subprocess`, `random`, `secrets` and
`time` in every source module, with one label-keyed exemption
`("process_supervision/windows_process.py", "subprocess")`. Stage 8 adds exactly
twelve pairs, each in the task that first imports the root in that module (Task
1: `database.py`/`sqlalchemy`; Task 2: `schema.py`/`sqlalchemy`,
`migration_runner.py`/`sqlalchemy` and `/alembic`, `migrations/env.py`/`sqlalchemy`
and `/alembic`, `versions/r0001_stage8_baseline.py`/`sqlalchemy` and `/alembic`;
Task 3: `registries.py`/`sqlalchemy`; Task 4: `unit_of_work.py`/`sqlalchemy`,
`repositories.py`/`sqlalchemy`; Task 5: `reconciliation_source.py`/`sqlalchemy`),
taking the set to 13. `test_the_subprocess_exemption_is_exactly_one_module_and_one_root`
is rewritten in Task 1 to iterate every pair (each exempted module must import
its root; each pair licenses nothing else), keeping its three Stage 7 controls and
adding three mirrors (`sqlalchemy` in `experiments/ports.py` fails; a planted
`persistence/probe.py` fails; `time` in `persistence/database.py` fails).
`codecs.py` and `diagnostics.py` import no infrastructure root. `random`,
`secrets`, `time` and `subprocess` stay denied for every persistence module.

**Deferred-definition guard.** `_DEFERRED_DEFINITIONS` holds 34 names. Stage 8
defines exactly one of them, `DatasetRepository`, released in Task 3 (count 33);
the seven-name representative-mutation list is unchanged (the name is not in it).
No Stage 8 class or function takes any other deferred name; concrete classes use
the `Sqlite*` prefix and table classes the `*Row` suffix.

<!-- released-names -->
Released (1): `DatasetRepository`.
<!-- /released-names -->

<!-- remaining-names -->
Remaining deferred (33), which no Stage 8 module may define under these exact
names: `ArtifactFinalizationPurpose`, `ArtifactFinalizer`, `ArtifactOwnerKind`,
`ArtifactRef`, `ArtifactRepository`, `ArtifactSourceRole`, `AuditSink`,
`AuditEvent`, `CandidateArtifact`, `CandidateArtifactRepository`,
`CandidateArtifactState`, `CandidateArtifactProducerKind`, `CandidateFinalization`,
`CanonicalFill`, `CanonicalOrder`, `ComparisonEligibilityService`, `ContentHasher`,
`EquityPoint`, `EvidenceFinalizationRequest`, `Fee`, `FinalizationResult`,
`MetricValue`, `OrderSide`, `OrderType`, `PortfolioSnapshot`, `PositionSnapshot`,
`PositionEffect`, `ResultFinalizationRequest`, `Result`, `RunManifest`,
`ingest_dataset`, `normalize_dataset`, `place_order`.
<!-- /remaining-names -->

**The Stage 7 "Stage 8 has not started" negatives.** Task 1 retires
`test_stage_eight_persistence_has_not_started` and its control
`test_the_stage_eight_path_scan_detects_each_shape` together with
`_stage8_shaped_paths`, `_STAGE8_SHAPED_PATTERN`, `_STAGE8_SCAN_ROOTS` and
`_STAGE8_SCAN_SKIP` (the regex `alembic|migration|\.db$|sqlite|sqlalchemy` over
`src`, `tests`, `scripts`, `schemas` and the repository root forbids every
Stage 8 path). The deferred-name half survives: `_STAGE8_AND_LATER_NAMES` (nine
finalization and manifest names) keeps its `in _DEFERRED_DEFINITIONS` and
`not in defined` assertions under a renamed test,
`test_stage_nine_finalization_names_stay_deferred`, so the Stage 9 negative is
never weakened.

**Dependency guards.** Task 1 edits `_EXPECTED_RUNTIME_REQUIREMENTS` (2 → 4, in
`pyproject.toml` order, alphabetical: `alembic…`, `pydantic>=2.12,<3`,
`pyyaml>=6.0.3,<7`, `sqlalchemy…`), the duplicate list at
`tests/safety/test_gitnexus_development_tooling.py` (`project["dependencies"]`),
and removes `"sqlalchemy"` and `"alembic"` from `_PROHIBITED_FAMILIES` (29 → 27;
the parametrized family test shrinks with it) while adding a positive control
that the two normalized names are now permitted. No guard, existing or new,
scans persistence for a `DELETE` statement: the `engine_slots` projection
rewrite of §4.3 is the one legitimate delete. `_EXPECTED_DEVELOPMENT_NAMES`
(8), the `[tool.mypy]` key set and its single `jsonschema` override are
unchanged (SQLAlchemy 2.x and Alembic ship `py.typed`; if the locked Alembic
release lacks it, Task 1 stops and reports rather than adding an override).
`test_lock_registry_artifacts_are_sha256_pinned` holds because uv records
registry hashes; Task 1's lock review confirms every new entry has a cp312 or
py3 `win_amd64` wheel so `no-build-isolation = true` never builds an sdist.

**Reader census (Stage 5 guard).** `_EXPECTED_READER_IMPLEMENTATIONS` (4)
gains `src/crypto_lab/persistence/registries.py::SqliteDiagnosticReader` in
Task 3 (5). The traversal scan then applies to it: no `while`, no `self.get`/
`self.get_many` call, no `resolve_causal_closure`, no attribute read of
`causal_diagnostic_ids`, and every `for` iterates a parameter — the reader uses
comprehensions over `execute(...).all()`.

**Bare-name and text scans.** `_BARE_FORBIDDEN_NAMES` (Stage 4) forbids the
identifiers `context`, `buffer`, `note` and `problem` anywhere in `src`; `env.py`
imports `from alembic import context as migration_context` and no persistence
identifier uses those names. `_ATTEMPT_TOKEN_CARRIERS` (Stage 6) stays four: no
persistence annotation names `AttemptToken`. `_TEXT_ONLY_SHELL_FILES`: no Stage 8
test contains the text `os.system`. `test_the_doubles_module_declares_no_thread_sleep_or_random_dependency`:
`tests/doubles/experiments.py` is not edited and never names SQLAlchemy.

**Architecture closure.** `tests/architecture/test_package_import_boundaries.py`
has no `persistence` closure. Task 1 adds `_PERSISTENCE = "crypto_lab.persistence"`,
`_ALLOWED_FOR_PERSISTENCE = ("crypto_lab.domain", "crypto_lab.experiments",
"crypto_lab.adapters", "crypto_lab.process_supervision", "crypto_lab.artifacts",
"crypto_lab.datasets", "crypto_lab.strategy", "crypto_lab.configuration",
"crypto_lab.persistence")`, `_PROHIBITED_FOR_PERSISTENCE = ("crypto_lab.capabilities",
"crypto_lab.cli", "crypto_lab.schema_registry")`, the same self-test
parametrizations the other closures have, and a positive anchor that grows per
task (Task 1: `domain`, `configuration`; Task 3: `artifacts`, `datasets`,
`strategy`; Task 4: `experiments`, `adapters`; Task 5: `process_supervision`).
The Stage 8 guard (Task 8) narrows the package-level allowance to the exact
module set of the header's dependency-direction bullet and adds
`_PROHIBITED_FOR_STRATEGY`/`_PROHIBITED_FOR_DATASETS`-style negatives proving
the two new port modules import only `domain` and their own package.

**Launcher and verifier pins (Task 2).** `tests/safety/test_uv_launcher.py`:
`_EXPECTED_NORMALIZED_SHA256` re-pinned; `migration-check` added to
`_PYTHON_BEARING_OPERATIONS` (`len(_EXPECTED_OPERATIONS) == 21`); one argv row
`(["migration-check"], ["RUN", _PYTHON, "-I", "-B", <scripts\verify_migrations.py>])`
and one rejection row `["migration-check", "extra"]`; the counted literals
(`ReparsePoint` 6, the python-path `Join-Path` 1) unchanged; `_ALLOWED_COMMANDS`
unchanged (the clause uses only `Resolve-ClosedRepositoryPath`).
`tests/safety/test_stage3_boundaries.py`: `_EXPECTED_VERIFIER_SHA256` re-pinned,
`_EXPECTED_VERIFICATION_PROFILES` gains `migration-check` between
`schema-generate-check` and `pytest-all` (10), `_ALLOWED_VERIFIER_COMMANDS` (8)
unchanged, and the mutation test keeps its closure. README's "ten-operation
workflow" sentence and the guide's "Complete verification" list become eleven
steps in the same commit.

**Subprocess importers (Stage 6 and 7 guards, Task 6).** `_SUBPROCESS_IMPORTERS`
(11) gains `tests/integration/persistence/test_wal_restart.py` (12); the Stage 7
guard's `_NUMBER_WORDS` already maps 12 to "twelve", so the guide sentence
becomes "the twelve `subprocess` importers (the ten of Stage 6, the Stage 7 fake
script and the Stage 8 interrupted-writer test)" and the "eleven" phrase joins
`_RETIRED_SUBPROCESS_IMPORTER_PHRASE`'s negative. The child is launched with a
list argv, `shell=False`, the venv interpreter and a single-line `-c` program;
the shell scan is unaffected.

**Status pins (Task 8).** `_STAGE8_ROADMAP_STATUS_LINE` (`**Status:** Approved
planning decomposition; Stages 1 through 8 complete`), `_STAGE8_ROADMAP_PLAN_SENTENCE`
(`Stages 1 through 8 have approved detailed implementation plans.`, also at
`test_gitnexus_development_tooling.py`), README `**Status:** Project 1 Stages 1-8
complete`, `_README_STAGE8_STATUS`, `_VERIFICATION_STAGE8_STATUS`,
`STAGE8_IMPLEMENTATION_COMMIT` (the Task 7 hash, asserted distinct from the
Stage 4–7 hashes, present once in the roadmap and absent from README and guide
after the Stage 7 hash leaves them), the Stage 7 forms turned into negatives, the
containment literal advanced to "Stage 9" with the guide's existing Stage 9
sentence (`Stage 9 can snapshot it without changing the published `$id`;`)
pinned positively and subtracted, `_VERIFICATION_NON_GOALS` reworded to drop the
word "persistence" (the sentence would otherwise be false) with its pin moved,
the Stage 7 row clause `Stage 8 not started |` → `Stage 8 complete |`,
`_STAGE8_ROADMAP_ROW` (the deferred row) turned negative, the five "Stage 8
complete"/"Stages 1-8"/"Stages 1 through 8" negatives inverted where the new
prose uses them, the Stage 5 guard's `_README_STAGE8_STATUS` import, and the new
`tests/safety/test_stage8_boundaries.py` pinning the Stage 8 completion row, the
Stage 9 deferred row, the approved-plan line and the Stage 8 focused-check
sentences. "exhaustiv" and "sandbox" stay absent from every Stage 8 sentence.

**Unchanged by proof.** Schema registry (35 = 11 + 9 + 7 + 8, four digest
blocks), `HashingProfile` (12), `DiagnosticCategory` (12),
`RECOGNIZED_NATIVE_EXIT_VALUES` (8), `STAGE5_DIAGNOSTIC_CODES` (6), every port
member set, `STAGE5/6/7_SOURCE_FILES` (18/14/12), the Stage 7 file counts
(12 + 11), `_ROOT_CONFINEMENT` (5 roots, none in persistence), the one `Popen`
call, `_FAKE_ADAPTER_ROOTS`, GitNexus pins, `pytest_options["pythonpath"]`,
hatch `packages`/`force-include`/sdist includes (migrations live in-package), the
`[tool.ruff]` exclusion list (this plan's fences are formatted before commit).

### 2.7 Toolchain gates

`ruff check` selects `B, DTZ, E, F, I, PT, RUF, S, UP` with only `S101` ignored
under `tests/`: every SQL string is a Core construct or `text()` over a literal
(S608), no `assert` in `src`, `PT011` needs `match=` on `pytest.raises(ValueError)`,
`RUF043` escapes regex metacharacters in `match=`, isort treats
`contract < crypto_lab < doubles < persistence_support` as first-party.
`ruff format --check` also formats the Python fences of this plan. Strict mypy
covers `src`, `tests` and `scripts`: every `X | MISSING` value is narrowed with
`isinstance` before use, SQLAlchemy `Row` access goes through `row._mapping`
with explicit `cast`-free typed accessors, `Result[...]` values are narrowed
with `isinstance(result, Success)`. `pytest-all` measures coverage over
`crypto_lab` only, so every persistence module counts, including `downgrade()`
bodies and every error branch (busy, snapshot, unique, foreign-key, CHECK,
trigger, read-only, unknown revision), each of which has a test. `pytest-focused`
accepts only `-o addopts=`, targets under `tests/` and a final `-q`. Every new
test file has a basename unique across `tests/`. Test function names stay at or
below 73 characters.

### 2.8 Dependency acquisition gates

Verified local facts at the planning base: `uv.lock` holds 30 packages and
neither `sqlalchemy`, `alembic`, `mako`, `markupsafe` nor `greenlet`; the uv
cache at `%LOCALAPPDATA%\uv\cache` holds no metadata or wheel for `sqlalchemy`,
`alembic`, `mako` or `greenlet` (it does hold `markupsafe` 3.0.3 and
`typing-extensions` 4.15/4.16, both `cp312`/`py3` `win_amd64`); the worktree's
`.venv` was created offline by the launcher `sync` profile (CPython 3.12.13). It
follows that `lock-resolve-offline` will fail for lack of registry metadata and
`sync` will fail for lack of distributions, so **both** approval-gated profiles
are expected to be needed. Nothing in this plan asserts a release number, a
transitive-dependency set or a cached artifact; each is read from the resolver's
output and recorded in the Task 1 ledger.

Task 1 runs, in order, stopping at each human gate:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 lock-resolve-offline
```

If it fails solely because registry metadata is missing, stop and obtain
explicit one-time approval for exactly:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 lock-acquire
```

After a generated lock:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 lock-check
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 sync
```

If `sync` fails solely because locked distributions are missing, stop and obtain
explicit one-time approval for exactly:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 sync-acquire
```

Then rerun `lock-check` and `sync` offline. Never hand-edit `uv.lock`; never run
`uv` outside the launcher; record whether each gate occurred. The lock review
(Task 1 step 6) confirms: every new entry uses the exact HTTPS PyPI registry
source with SHA-256 hashes on every artifact; each has a `win_amd64` wheel for
CPython 3.12 (`no-build-isolation = true` must never trigger an sdist build);
the resolved SQLAlchemy is a 2.x release and the resolved Alembic a 1.x release;
each ships `py.typed`; and no engine, exchange, network client, dataframe,
Parquet, LLM, GitNexus, Docker or deployment package entered the lock. If any
confirmation fails, Task 1 stops and reports; it does not widen an override or
relax a pin.

Library facts this plan relies on and the probe that validates each before any
task depends on it (all in Task 1 or Task 2, all executable offline once the
packages are installed):

| Relied-on behaviour | Validation gate |
|---|---|
| Disabling the DBAPI's implicit transactions (`isolation_level = None` on connect) and issuing `BEGIN` from the engine's begin hook gives one explicit deferred transaction per connection | Task 1 probe: two connections, T1 `BEGIN` + read, T2 writes and commits, T1's write raises with `sqlite_errorcode == 517` (`SQLITE_BUSY_SNAPSHOT`) |
| A write blocked by another writer waits at most `busy_timeout` then raises with `sqlite_errorcode == 5` | Task 1 probe with `busy_timeout_ms = 100`, measured wall time below one second |
| Unique and primary-key violations arrive as `IntegrityError` with `sqlite_errorcode` in `{2067, 1555}`; foreign-key, CHECK and trigger violations with `{787, 275, 1811}`; a statement failure does not end the SQLite transaction (the rollback is explicit) | Task 1 probe over a two-table fixture |
| The wrapped DBAPI exception exposes `sqlite_errorcode` (CPython 3.11+) through SQLAlchemy's `.orig` | Task 1 probe |
| Each physical connection can be re-used across threads once returned to the pool (`check_same_thread=False`) and PRAGMAs applied in the connect hook persist for the connection's life | Task 1 probe: apply, return, re-check-out from another thread, read back |
| Pool exhaustion raises the pool's own timeout error (not a DBAPI error) after the checkout timeout; `begin()` classifies it separately as `PERSISTENCE.STORAGE_UNAVAILABLE` | Task 1 probe with a pool of one and a second checkout |
| An abandoned, never-finished transaction is reclaimed (rolled back, connection returned) only when the pool's finalizer runs, which the `Connection`/transaction reference cycle can delay until the cyclic collector runs; no test relies on it — the SQLite harness rolls back every open transaction at teardown (§7.1) | Task 4 probe: abandon a transaction, `gc.collect()`, assert the writer lock is released and the pool checked-in count is restored |
| A statement refused with a constraint or busy error leaves the SQLite transaction open and usable; an I/O-class error may end it, which the DBAPI's `in_transaction` reports | Task 1 probe: refused `INSERT` then successful `INSERT` and `COMMIT` on the same connection |
| `SAVEPOINT`/`ROLLBACK TO`/`RELEASE` (`Connection.begin_nested()`) work under the explicit-`BEGIN` recipe and roll back exactly the statements issued after the savepoint | Task 1 probe: `INSERT`, `SAVEPOINT`, `INSERT`, refused `INSERT`, `ROLLBACK TO`, `COMMIT` → only the first row is durable |
| `PRAGMA journal_mode=WAL` persists in the file; `foreign_keys`, `synchronous`, `busy_timeout` are per connection | Task 1 probe: reopen and read back |
| Alembic's `Config` accepts `script_location` set programmatically and `command.upgrade` runs `env.py` with a caller-supplied connection in `config.attributes["connection"]` | Task 2 probe (the first `apply_migrations` test) |
| `ScriptDirectory.get_heads()` returns exactly one head; `MigrationContext.configure(connection).get_current_revision()` returns `None` on an empty database and the stamped id afterwards; `alembic.autogenerate.compare_metadata` returns an empty list after upgrade | Task 2 tests; the drift comparison's known SQLite blind spots (CHECK expressions, trigger DDL) are covered by Task 2's explicit `sqlite_master` assertions |
| Alembic's version-file discovery ignores `versions/__init__.py`; `env.py` can detect an established proxy | Task 2 tests (reading 16 and 17) |
| Alembic and SQLAlchemy type-check under strict mypy without overrides | Task 1 `mypy-all` after `sync` |

---

## 3. Existing contract to storage mapping (matrix A)

### 3.1 Existing facts: the records Stage 8 persists

Every row below is a fact of the committed source (module and class named); the
"Stage 8 table" column is this plan's proposal, detailed in §3.3.

| Record (module) | Identity | Revision / mutability | Timestamps | Fields / `MISSING`-typed | Self-verifying hash on load | Stage 8 table |
|---|---|---|---|---|---|---|
| `ExperimentRecord` (`domain/experiment.py`), embedding `ExperimentSpec` and `RetryPolicy` | `experiment_id` | `revision >= 0`, CAS; spec frozen at `QUEUED` (service rule) | `created_at_utc`, `updated_at_utc >= created_at_utc` | 10 / 2 (`slot_compatibility`, `cancellation_correlation_id`) | `spec_hash == experiment_spec_hash(spec)` | `experiments` (+ `engine_slots` projection; + the `ConfigSnapshot` columns below) |
| `ConfigSnapshot` (`configuration/snapshot.py`), produced by `snapshot_configuration(config)` | the owning experiment (one snapshot per row; the record itself has no identifier) | frozen at `QUEUED`; replaceable while `DRAFT`/`VALIDATED`; never cleared | none | 4 / 0 (`schema_version`, `configuration_json` ≤ `MAX_CONFIGURATION_BYTES`, `configuration_audit_hash`, `material_base_configuration_hash`) | its validator re-parses `configuration_json` as `ApplicationConfig`, re-canonicalizes it and re-derives both hashes | `experiments` (four nullable columns, one per field, §3.3.1; reading 22) |
| `EngineRunRecord` (`domain/engine_run.py`) | `run_id`; unique `(experiment_id, logical_slot_id, attempt_number)` | `revision`, CAS; a terminal record accepts no CAS | `created_at_utc`, `updated_at_utc` | 18 / 5 (`predecessor_run_id`, `retry_reason`, `primary_terminal_diagnostic_id`, `availability_observation_id`, `finalization_deadline_utc` — the last forced absent today) | none (field rules only) | `engine_runs` |
| `CommandInvocationRecord` (`domain/command_invocation.py`), nesting `ProcessIdentity` | `invocation_id`; partial unique open `(run_id, command_kind)` | `revision`, CAS per transition and per write-once enrichment | `created_at_utc`, `updated_at_utc`, `launch_attempted_at_utc`, `deadline_utc`, `process_started_at_utc`, `completed_at_utc`, `cleanup_completed_at_utc` | 25 / 11 | none; `deadline_utc == launch_attempted_at_utc + timeout_seconds`, `process_exit_category == process_exit_category_for(native_exit_value)` | `command_invocations` |
| `RetryDecisionRecord` (`domain/retry.py`), embedding `RetryPolicy` | `(logical_slot_id, predecessor_run_id)` | none; immutable at insertion | `decided_at_utc` (excluded from the semantic projection) | 16 / 5 | none; `reserved_successor_attempt_number == created_attempt_count + 1` | `retry_decisions` |
| `RunEvent` (`adapters/events.py`), six payload classes | `(invocation_id, sequence)`; unique `event_id`; idempotent on `content_hash` | none; insert-only | `timestamp_utc`, `received_at_utc` | 13 / 0 (payload-nested `MISSING` fields) | `content_hash` (`RUN_EVENT_CONTENT_V1`, excludes `received_at_utc`, `wire_event_hash`) | `run_events` |
| `RuntimeAvailabilityObservation` (`domain/descriptors.py`) | `availability_observation_id` | none; immutable | `observed_at_utc < expires_at_utc` | 14 / 1 (`reason_code` present iff `not available`) | none | `runtime_availability_observations` |
| `Diagnostic` (`domain/diagnostics.py`) | `diagnostic_id` | none; immutable | `timestamp_utc` (legacy `UtcDateTime` alias, same runtime) | 15 / 4 (`experiment_id`, `run_id`, `invocation_id`, `engine`) | none; `details` bounded recursive JSON (depth 8, 256 nodes, 16 384 canonical bytes, no secret-like keys) | `diagnostics` |
| `StrategyVersion` (`strategy/versioning.py`), embedding `StrategySpec` and `StrategySourceProvenance` | `content_hash`; `strategy_version_id` non-material | none; immutable | `created_at_utc`, `source_provenance.observed_at_utc` | 9 / 0 | `content_hash` recomputed by `validate_identity_is_recomputed` | `strategy_versions` |
| `DatasetDescriptor`, `DatasetPartition` (`datasets/models.py`) | `dataset_id` + unique `content_hash`; `partition_id`, unique `(dataset_id, ordinal)` | none; immutable | `start_utc < end_utc`, `created_at_utc`, optional `imported_at_utc` | 26 / 2 (`timeframe`, `imported_at_utc`); partition 14 / 0 | `dataset_metadata_hash` through `validate_dataset_identity(descriptor, partitions)` | `datasets`, `dataset_partitions` |
| `ArtifactOwnerRef` (`artifacts/ownership.py`), six variants | `artifact_owner_hash(owner)` (`ARTIFACT_OWNER_V1`) | none; value object | none | RUN 3 / 1, EXPERIMENT 1, DATASET 1, STRATEGY 2 / 2 (exactly one present), ADAPTER 4 / 2 (engine pair co-present), SYSTEM 2 | none | `artifact_owners` |

Existing facts that shape every column choice:

- `MISSING` is an omitted key, never `null`, in both dump modes; no top-level
  field of any record admits `None`; the only JSON `null` in any persisted
  document is a leaf inside `details`. An empty tuple renders as `[]` and is
  distinct from absence.
- `format_utc` renders 20 characters (`…SSZ`) when `microsecond == 0` and 27
  (`…SS.ffffffZ`) otherwise; the two forms do not sort chronologically as text.
- `format_decimal` renders canonical decimal text of at most 256 characters,
  no exponent, no negative zero, no non-finite values; canonical JSON forbids
  `float` outright.
- Strict Python-mode validation refuses text for `datetime`, `Decimal` and enum
  fields; JSON-mode validation accepts exactly the canonical text forms.
- Identifiers are fixed-length prefixed lowercase UUID4 text (39–42
  characters); `Sha256` is exactly 64 lowercase hex characters.
- `native_exit_value` spans `-2147483648..4294967295`; `pid` reaches
  `4294967295`; counters and declared sizes reach `2**53 - 1`; detail integers
  are signed 64-bit.

### 3.2 Encodings and the NULL rules (single authority)

| Encoding | Domain form | Column form | Egress rule |
|---|---|---|---|
| E1 identifier / hash / normalized identifier / semantic version / bounded text | `str` aliases | `TEXT NOT NULL`, CHECK on prefix and length for identifiers, CHECK `length = 64 AND NOT GLOB '*[^0-9a-f]*'` for hashes | verbatim |
| E2 enum | `StrEnum` member | `TEXT NOT NULL CHECK (col IN (...members...))`; the member list is generated from the enum at metadata build time so it can never drift | the text value; the record's enum validator accepts it in JSON mode |
| E3 boolean | `bool` | `INTEGER NOT NULL CHECK (col IN (0, 1))` | `col == 1` |
| E4 bounded integer | `int` with `Field(ge, le)` | `INTEGER NOT NULL CHECK (lo <= col AND col <= hi)` (64-bit) | verbatim |
| E5 UTC instant | `CalendarValidUtcDateTime` / `UtcDateTime` | `INTEGER` microseconds since `1970-01-01T00:00:00Z`: `(value - EPOCH) // timedelta(microseconds=1)` on the UTC-normalized `datetime` (exact, negative before 1970); range CHECK `-62135596800000000 <= col <= 253402300799999999` (`0001-01-01T00:00:00Z` through `9999-12-31T23:59:59.999999Z`, the domain's own grammar) | `format_utc(EPOCH + timedelta(microseconds=col))`; the record validates the text |
| E6 canonical decimal | `CanonicalDecimal` | `TEXT NOT NULL CHECK (length(col) <= 256)`; never `REAL` | verbatim text; the record's `parse_decimal` validates it |
| E7 canonical-JSON snapshot | nested `CanonicalModel`, tuple of models, `details`, sorted identifier tuple | `TEXT NOT NULL CHECK (json_valid(col))`, bytes = `canonical_json_text(value)` (sorted keys, compact separators, UTF-8, no BOM) | `json.loads(col, parse_constant=_refuse_constant)` then embedded in the egress payload; the record re-validates every nested invariant |
| E8 ordered identifier tuple (`diagnostic_ids`, `causal_diagnostic_ids`) | sorted unique tuple | E7 (a JSON array) plus CHECK `json_array_length(col) <= bound` | the parsed array; the record's sorted-unique validator rejects a corrupted order |

`NULL` rules, one state per column:

- **N1** A column that maps an `X | MISSING` field is nullable and `NULL` means
  exactly `MISSING`; egress omits the key when the column is `NULL` and never
  emits JSON `null`.
- **N2** A column that maps a required field is `NOT NULL`; an empty tuple is
  the JSON text `[]`, never `NULL`.
- **N3** The state-governed presence rules of the records are repeated as CHECK
  constraints over the `NULL`-ness of N1 columns (§3.3), so a row that a record
  validator would refuse cannot be inserted by a defective codec either.
- **N4** The one field forced `MISSING` by today's validators
  (`EngineRunRecord.finalization_deadline_utc`) has no column; ingress with a
  present value is refused with `CORE.INVARIANT_VIOLATION`; egress yields
  `MISSING`. (`CommandInvocationRecord.stderr_artifact_id` is not such a field:
  the record admits it on any terminal state as a write-once enrichment, so it is
  an ordinary N1 column, §3.3.4.)
- **N5** A nested value object with a fixed field set (`AdapterIdentity`,
  `EngineIdentity`, `ProcessIdentity`) is flattened to typed columns; a nested
  value object whose order or shape is part of a hash or of a validator
  (`ExperimentSpec`, `RetryPolicy`, `SlotCompatibility` tuple, `payload`,
  `details`, `StrategySpec`, `DatasetDescriptor` collections) is an E7 snapshot.
  Flattened columns of an N1 parent are all `NULL` or all present (CHECK).
- **N6** Every typed column that projects a value also present inside an E7
  snapshot (`experiments.strategy_version_hash`/`dataset_version_hash`, the
  `engine_slots` rows, `strategy_versions.strategy_id`/`strategy_version_id`/
  `hashing_profile_version`/`created_at_utc`, the typed columns of `datasets` and
  `dataset_partitions`) is index-only: it is written from the same record in the
  same statement, never read to rebuild a record, and the E7 column is
  authoritative. Agreement is proven by the §7.3 property "decode → encode
  reproduces the same column values" and by the projection rows of
  `consistency_report()` (§4.6); a frozen experiment's two hash projections are
  additionally covered by T-EXP-FROZEN.

Egress is one mechanism for every record (`codecs.py`): assemble a JSON-mode
payload from the row (E1–E8, N1–N5), then
`Record.model_validate_json(canonical_json_bytes(payload))`. A
`ValidationError` is `CORE.INVARIANT_VIOLATION` with `table`, `identity` and the
first error location in `details` (reading 10). Ingress is the inverse projection
of an already-validated record; the codec never re-derives a hash, only copies it
(the record validators recompute on the next egress).

### 3.3 Tables (proposed relational design)

Conventions: every table has `schema_version TEXT NOT NULL CHECK (schema_version = '1.0.0')`
where the record carries one (spec 10.4). Foreign keys are `ON DELETE RESTRICT
ON UPDATE RESTRICT` (spec 23.3.1); the only `DELETE` any Stage 8 code path
issues is the `engine_slots` projection rewrite of §3.3.2/§4.3. Enum CHECKs are
generated from the domain enumerations. "Owning task" is the task that maps the
table's repository; the table itself is created by Task 2's baseline revision.
Every index below is created by the baseline revision and asserted by Task 2's
`sqlite_master` test.

#### 3.3.1 `experiments` (owning task 4)

| Column | Type / encoding | Source field | NULL |
|---|---|---|---|
| `experiment_id` | TEXT PK, E1 (`exp_`, 40) | `experiment_id` | no |
| `schema_version` | TEXT, literal | `schema_version` | no |
| `state` | E2 `ExperimentState` | `state` | no |
| `spec` | E7 (`ExperimentSpec`, includes `RetryPolicy`, `configuration_hash`, `created_at_utc`) | `spec` | no |
| `spec_hash` | E1 hash | `spec_hash` | no |
| `strategy_version_hash` | E1 hash (projection of `spec.strategy_version_hash`) | — | no |
| `dataset_version_hash` | E1 hash (projection of `spec.dataset_version_hash`) | — | no |
| `slot_compatibility` | E7 (tuple of `SlotCompatibility`), N1 | `slot_compatibility` | yes |
| `cancellation_correlation_id` | TEXT (1..128), N1 | `cancellation_correlation_id` | yes |
| `created_at_utc`, `updated_at_utc` | E5 | same | no |
| `revision` | E4 `>= 0` | `revision` | no |
| `configuration_snapshot_schema_version` | TEXT, CHECK `col = '1.0.0'` (the record's envelope literal, stored like every other table's `schema_version`; spec 10.4) | `ConfigSnapshot.schema_version` (reading 22) | yes, until frozen |
| `configuration_snapshot_json` | TEXT, CHECK `json_valid(col) AND length(CAST(col AS BLOB)) <= 1048576` (`MAX_CONFIGURATION_BYTES`); the bytes are `ConfigSnapshot.configuration_json` verbatim (already canonical JSON of the `ApplicationConfig`) | `ConfigSnapshot.configuration_json` (reading 22) | yes, until frozen |
| `configuration_audit_hash` | E1 hash | `ConfigSnapshot.configuration_audit_hash` | yes, until frozen |
| `material_base_configuration_hash` | E1 hash | `ConfigSnapshot.material_base_configuration_hash` | yes, until frozen |

Constraints: CHECK `updated_at_utc >= created_at_utc`; CHECK
`CASE WHEN state IN ('DRAFT','VALIDATED') THEN slot_compatibility IS NULL WHEN state = 'CANCELLED' THEN 1 ELSE slot_compatibility IS NOT NULL END`;
CHECK `(state = 'CANCELLED') = (cancellation_correlation_id IS NOT NULL)`;
CHECK `(configuration_snapshot_json IS NULL) = (configuration_snapshot_schema_version IS NULL) AND (configuration_snapshot_json IS NULL) = (configuration_audit_hash IS NULL) AND (configuration_snapshot_json IS NULL) = (material_base_configuration_hash IS NULL)`
(the snapshot is present whole or absent whole across its four columns; it is
not a record field, so rule N1 does not apply — `NULL` means "not yet
frozen"). The four columns are the four fields of `ConfigSnapshot`, so egress
supplies nothing the row does not hold.
Indexes: `(state, created_at_utc)`, `strategy_version_hash`, `dataset_version_hash`.
Triggers §3.4: T-EXP-TERMINAL, T-EXP-FROZEN, T-EXP-QUEUE-SNAPSHOT,
T-EXP-SNAPSHOT-FROZEN. The two hash projections are not
foreign keys: spec 11.3 says the references "resolve before queueing", a check the
Stage 10 composition performs against the registries (§1.3); a DRAFT experiment
may lawfully cite a not-yet-registered hash. Deletion is never issued.

The snapshot columns (reading 22): written only by
`SqliteConfigurationSnapshotWriter.freeze(experiment_id, snapshot)` (§4.4),
which the composition root calls while the experiment is `DRAFT` or
`VALIDATED` and before `queue_experiment`; read back by
`SqliteConfigurationSnapshotWriter.get`, which rebuilds a `ConfigSnapshot`
through its own validator (a tampered byte fails as `CORE.INVARIANT_VIOLATION`).
The `VALIDATED → QUEUED` compare-and-swap (§4.3.1 step d′) refuses a row whose
snapshot is absent or disagrees with the frozen spec, and T-EXP-QUEUE-SNAPSHOT
refuses the same edge at the SQL layer; once the row is at or after `QUEUED`
the four columns are immutable (T-EXP-SNAPSHOT-FROZEN). The columns are not
part of `ExperimentRecord` and never enter the record's egress payload; the
codec ignores them, and the record compare-and-swap of §4.3.1 step e never
names them in its `SET` list. A row inserted directly at or after `QUEUED` through
`ExperimentRepository.add` (test scaffolding — production inserts only
`DRAFT` rows through `create_experiment`) carries no snapshot and is counted
by `consistency_report().queued_without_snapshot` (§4.6).

#### 3.3.2 `engine_slots` (owning task 4; projection of `spec.selected_engine_slots`)

| Column | Type / encoding | Source | NULL |
|---|---|---|---|
| `experiment_id` | TEXT FK → `experiments` RESTRICT; PK part 1 | owning experiment | no |
| `logical_slot_id` | TEXT, E1 (`slot_`, 41); PK part 2 | `SelectedEngineSlot.logical_slot_id` | no |
| `slot_ordinal` | E4 `0..7` | `slot_ordinal` | no |
| `adapter_name`, `adapter_version`, `engine_name`, `engine_version` | E1 | `adapter.*`, `engine.*` | no |

Constraints: `PRIMARY KEY (experiment_id, logical_slot_id)` (reading 7: a
slot identifier is unique within its experiment, and the shared fixtures give
every experiment the same identifiers, so the key is composite and there is no
global `logical_slot_id` key); UNIQUE `(experiment_id, slot_ordinal)`. The
primary key is the composite parent of `engine_runs` and `retry_decisions`.
Written by
`SqliteExperimentRepository.add` (one row per slot) and by `compare_and_swap`
when the stored state is `DRAFT` or `VALIDATED` and `spec_hash` changed (delete
the experiment's rows and reinsert — legal because no `engine_runs` row can
reference a pre-`QUEUED` experiment's slots; the RESTRICT key proves it). The
rows are never read to rebuild a record (the spec JSON is the source); they exist
for the composite foreign key and the spec 23.3.1 lookup index
`(adapter_name, adapter_version, engine_name, engine_version)`. Byte agreement
with the spec is asserted by Task 4's projection test after every write.

#### 3.3.3 `engine_runs` (owning task 4)

| Column | Type / encoding | Source field | NULL |
|---|---|---|---|
| `run_id` | TEXT PK, E1 (`run_`, 40) | `run_id` | no |
| `schema_version` | literal | | no |
| `experiment_id` | TEXT FK → `experiments` RESTRICT | `experiment_id` | no |
| `logical_slot_id` | TEXT; FK `(experiment_id, logical_slot_id)` → `engine_slots(experiment_id, logical_slot_id)` RESTRICT | `logical_slot_id` | no |
| `attempt_number` | E4 `1..5` | `attempt_number` | no |
| `attempt_token_hash` | E1 hash | `attempt_token_hash` | no |
| `state` | E2 `EngineRunState` | `state` | no |
| `adapter_name`, `adapter_version`, `engine_name`, `engine_version` | E1 (N5 flatten) | `adapter.*`, `engine.*` | no |
| `request_hash` | E1 hash | `request_hash` | no |
| `predecessor_run_id` | TEXT FK → `engine_runs(run_id)` RESTRICT, N1 | `predecessor_run_id` | yes |
| `retry_reason` | E2 `RetryTerminalState`, N1 | `retry_reason` | yes |
| `primary_terminal_diagnostic_id` | TEXT (`diag_`, 41), N1, indexed, **no foreign key** (§1.4 row 1) | `primary_terminal_diagnostic_id` | yes |
| `availability_observation_id` | TEXT FK → `runtime_availability_observations` RESTRICT, N1 | `availability_observation_id` | yes |
| `created_at_utc`, `updated_at_utc` | E5 | same | no |
| `revision` | E4 `>= 0` | `revision` | no |

No `finalization_deadline_utc` column (N4). Constraints: `run_id` is the
primary identity; UNIQUE `(experiment_id, logical_slot_id, attempt_number)` (the
three-field attempt identity of spec 17.2 and 23.3, reading 7 — there is **no**
unscoped `(logical_slot_id, attempt_number)` index); the composite foreign key
`(experiment_id, logical_slot_id) → engine_slots` is what makes a run belong to
a slot of its own experiment (a run naming a slot that exists only under
another experiment is refused, §5.1 C-28); UNIQUE `(experiment_id, run_id)`
(composite parent for `artifact_owners` and `retry_decisions`; `run_id` alone is
already unique, the pair exists so those keys carry the experiment agreement);
partial UNIQUE INDEX
`(experiment_id, logical_slot_id) WHERE state IN ('PENDING','VALIDATING','READY','STARTING','RUNNING')`
(spec 23.3.1 "active-attempt partial uniqueness"); CHECK
`(attempt_number > 1) = (predecessor_run_id IS NOT NULL)`; CHECK
`(attempt_number > 1) = (retry_reason IS NOT NULL)`; CHECK `predecessor_run_id IS NULL OR predecessor_run_id <> run_id`;
CHECK `(state IN ('FAILED','CANCELLED','TIMED_OUT','NOT_APPLICABLE','UNAVAILABLE')) = (primary_terminal_diagnostic_id IS NOT NULL)`;
CHECK `CASE WHEN state IN ('PENDING','VALIDATING') THEN availability_observation_id IS NULL WHEN state IN ('READY','STARTING','RUNNING','SUCCEEDED','SUCCEEDED_WITH_WARNINGS','UNAVAILABLE') THEN availability_observation_id IS NOT NULL ELSE 1 END`;
CHECK `updated_at_utc >= created_at_utc`. Indexes: `state`,
`predecessor_run_id`, `primary_terminal_diagnostic_id`,
`availability_observation_id`. Trigger T-RUN-TERMINAL. Adapter/engine agreement
with the slot row is an application rule (`create_attempt`/`create_successor`
re-check the spec slot) and a Task 4 consistency query, not a cross-table CHECK
(SQLite forbids subqueries in CHECK).

#### 3.3.4 `command_invocations` (owning task 4; read by task 5)

| Column | Type / encoding | Source field | NULL |
|---|---|---|---|
| `invocation_id` | TEXT PK, E1 (`inv_`, 40) | `invocation_id` | no |
| `schema_version` | literal | | no |
| `command_kind` | E2 `CommandKind` | `command_kind` | no |
| `adapter_name`, `adapter_version` | E1 | same | no |
| `run_id` | TEXT FK → `engine_runs` RESTRICT, N1 | `run_id` | yes |
| `request_hash` | E1 hash | `request_hash` | no |
| `timeout_seconds` | E4 | `timeout_seconds` | no |
| `state` | E2 `CommandInvocationState` | `state` | no |
| `process_created` | E3 | `process_created` | no |
| `launch_attempted_at_utc`, `deadline_utc` | E5, N1 | same | yes |
| `process_started_at_utc` | E5, N1 | same | yes |
| `pid`, `creation_identity`, `executable_path`, `executable_hash`, `supervisor_instance_id` | E4 `1..4294967295`, E1 (≤1024), E1 (≤1024), E1 hash, E1 (≤1024); N1 + N5 flatten of `ProcessIdentity` | `pid_identity.*` | yes (all five together) |
| `completed_at_utc` | E5, N1 | `completed_at_utc` | yes |
| `native_exit_value` | E4 `-2147483648..4294967295`, N1 | `native_exit_value` | yes |
| `process_exit_category` | E2 `ProcessExitCategory`, N1 | `process_exit_category` | yes |
| `cleanup_complete` | E3 | `cleanup_complete` | no |
| `cleanup_completed_at_utc` | E5, N1 | same | yes |
| `stderr_artifact_id` | TEXT (`art_`, 40), N1, **no foreign key** (Stage 9 adds the `artifact_refs` key and the `EVIDENCE`/owner rule, §1.4) | `stderr_artifact_id` | yes |
| `primary_diagnostic_id` | TEXT (`diag_`), N1, indexed, **no foreign key** | `primary_diagnostic_id` | yes |
| `diagnostic_ids` | E8, bound 64 | `diagnostic_ids` | no |
| `created_at_utc`, `updated_at_utc` | E5 | same | no |
| `revision` | E4 `>= 0` | `revision` | no |

Constraints (the spec 15.2 table as CHECKs, from the record's
`_validate_state_row`, `_validate_terminal_partition` and
`_validate_co_occurrence`):

- `(command_kind = 'DESCRIBE') = (run_id IS NULL)`;
- `CASE command_kind WHEN 'DESCRIBE' THEN timeout_seconds BETWEEN 1 AND 300 WHEN 'VALIDATE' THEN timeout_seconds BETWEEN 1 AND 1800 ELSE timeout_seconds BETWEEN 1 AND 604800 END`;
- `(launch_attempted_at_utc IS NULL) = (deadline_utc IS NULL)` and
  `deadline_utc IS NULL OR deadline_utc = launch_attempted_at_utc + timeout_seconds * 1000000`;
- the six process columns share one `NULL`-ness and
  `(process_created = 1) = (pid IS NOT NULL)`;
- `(native_exit_value IS NULL) = (process_exit_category IS NULL)` and
  `process_exit_category IS NULL OR process_exit_category = CASE native_exit_value WHEN 0 THEN 'SUCCESS' WHEN 10 THEN 'VALIDATION_FAILURE' WHEN 20 THEN 'NOT_APPLICABLE' WHEN 30 THEN 'UNAVAILABLE' WHEN 40 THEN 'RUNTIME_FAILURE' WHEN 50 THEN 'CANCELLED' WHEN 60 THEN 'TIMED_OUT' WHEN 70 THEN 'PROTOCOL_VIOLATION' ELSE 'RUNTIME_FAILURE' END`;
- `(cleanup_complete = 1) = (cleanup_completed_at_utc IS NOT NULL)`;
- `(state IN ('EXITED','FAILED_TO_START','CANCELLED','TIMED_OUT','PROTOCOL_FAILED')) = (completed_at_utc IS NOT NULL)`;
- non-terminal rows: `state IN (terminal five) OR (cleanup_complete = 0 AND primary_diagnostic_id IS NULL AND native_exit_value IS NULL AND stderr_artifact_id IS NULL)` (so `stderr_artifact_id` is terminal-only, as `_validate_terminal_partition` requires);
- per state: `PENDING` → `deadline_utc IS NULL AND process_created = 0`;
  `STARTING` → `deadline_utc IS NOT NULL AND process_created = 0`; `RUNNING` →
  `deadline_utc IS NOT NULL AND process_created = 1`; `EXITED` → `deadline_utc IS NOT NULL AND process_created = 1 AND native_exit_value IS NOT NULL AND (native_exit_value IN (0,10,20,30,40,50,60,70) OR primary_diagnostic_id IS NOT NULL)`;
  `FAILED_TO_START` → `deadline_utc IS NOT NULL AND process_created = 0 AND native_exit_value IS NULL AND primary_diagnostic_id IS NOT NULL`;
  `CANCELLED` → `primary_diagnostic_id IS NOT NULL AND (process_created = 0 OR deadline_utc IS NOT NULL)`;
  `TIMED_OUT` → `deadline_utc IS NOT NULL AND primary_diagnostic_id IS NOT NULL`;
  `PROTOCOL_FAILED` → `deadline_utc IS NOT NULL AND process_created = 1 AND primary_diagnostic_id IS NOT NULL`;
- `json_array_length(diagnostic_ids) <= 64`; `updated_at_utc >= created_at_utc`.

Membership of `primary_diagnostic_id` in `diagnostic_ids` and the sorted-unique
order of the array are record-validator rules (SQLite CHECK admits no subquery);
they hold on ingress (validated record) and on egress (re-validation).
UNIQUE `(run_id, invocation_id)` (composite parent for `run_events` and
`artifact_owners`). Partial UNIQUE INDEX `(run_id, command_kind) WHERE run_id IS NOT NULL AND state IN ('PENDING','STARTING','RUNNING')`
(the port's "one open invocation per run and kind"). Indexes: `(state,
deadline_utc)`; `(run_id, command_kind, launch_attempted_at_utc)`;
`(creation_identity, pid)` (durable process identity); `(state, cleanup_complete,
created_at_utc, invocation_id)` (the reconciliation listing); `(created_at_utc,
invocation_id)`; `primary_diagnostic_id`. Trigger T-INV-TERMINAL. Write-once
enrichment (no overwrite of a present native exit, cleanup, `stderr_artifact_id`
or diagnostic fact; `stderr_artifact_id` may become present through
`enrich_invocation` on a terminal record) is the record pair rule
`assert_write_once_enrichment`, enforced by the Stage 5 operation before the CAS
and by the codec's egress; the terminal trigger keeps the state fixed at the SQL
level.

#### 3.3.5 `run_events` (owning task 4)

| Column | Type / encoding | Source field | NULL |
|---|---|---|---|
| `invocation_id` | TEXT, E1 (`inv_`) | `invocation_id` | no |
| `sequence` | E4 `1..1000000` | `sequence` | no |
| `event_id` | TEXT UNIQUE, E1 (`evt_`, 40) | `event_id` | no |
| `run_id` | TEXT FK → `engine_runs` RESTRICT; composite FK `(run_id, invocation_id)` → `command_invocations(run_id, invocation_id)` RESTRICT | `run_id` | no |
| `schema_version`, `protocol_version` | literals | same | no |
| `attempt_token_hash`, `wire_event_hash`, `content_hash` | E1 hash | same | no |
| `event_type` | E2 `ProtocolEventType` | `event_type` | no |
| `timestamp_utc`, `received_at_utc` | E5 | same | no |
| `payload` | E7 (the six-way union rendered by the record's own serializer) | `payload` | no |

PRIMARY KEY `(invocation_id, sequence)`. The composite foreign key enforces
"invocation must belong to that same run" and, because `run_id` is `NOT NULL`,
that a `DESCRIBE` invocation never owns an event. Indexes: `(run_id,
received_at_utc)`, `event_type`, `wire_event_hash`, `run_id`. Trigger
T-APPEND-ONLY. Contiguity: reading 14.

#### 3.3.6 `retry_decisions` (owning task 4)

| Column | Type / encoding | Source field | NULL |
|---|---|---|---|
| `logical_slot_id`, `predecessor_run_id` | TEXT, E1; PK `(logical_slot_id, predecessor_run_id)` — the port's key. `predecessor_run_id` is a globally unique `run_id`, so it alone identifies the predecessor and, through `engine_runs`, its experiment; `logical_slot_id` in the key is the port's redundant consistency component (it must equal the predecessor's slot), not a second scope, so no `experiment_id` is added to the key mechanically | same | no |
| `schema_version` | literal | | no |
| `experiment_id` | TEXT FK → `experiments` RESTRICT; composite FK `(experiment_id, predecessor_run_id)` → `engine_runs(experiment_id, run_id)` RESTRICT (the decision's experiment is the predecessor's); composite FK `(experiment_id, logical_slot_id)` → `engine_slots(experiment_id, logical_slot_id)` RESTRICT (the slot belongs to that experiment); together they pin the decision to the predecessor's own slot | `experiment_id` | no |
| `experiment_spec_hash` | E1 hash | same | no |
| `retry_policy` | E7 (`RetryPolicy`) | `retry_policy` | no |
| `created_attempt_count` | E4 `1..5` | same | no |
| `predecessor_terminal_state` | E2 restricted to the five non-success terminals (reading: the runtime narrows the published enum) | same | no |
| `primary_terminal_diagnostic_id` | TEXT (`diag_`), indexed, **no foreign key** | same | no |
| `outcome` | E2 `RetryDecisionOutcome` | `outcome` | no |
| `denial_reason` | E2 `RetryDenialReason`, N1 | same | yes |
| `hard_block_error_code` | TEXT (3..128), N1 | same | yes |
| `availability_observation_id` | TEXT FK → `runtime_availability_observations` RESTRICT, N1 | same | yes |
| `retry_not_before_utc` | E5, N1 | same | yes |
| `reserved_successor_attempt_number` | E4 `2..5`, N1 | same | yes |
| `decided_at_utc` | E5 | same | no |

CHECKs: `(outcome = 'DENIED') = (denial_reason IS NOT NULL)`;
`(denial_reason IS 'HARD_BLOCKED_OUTCOME') = (hard_block_error_code IS NOT NULL)`;
`(outcome = 'ALLOWED') = (retry_not_before_utc IS NOT NULL)`;
`(outcome = 'ALLOWED') = (reserved_successor_attempt_number IS NOT NULL)`;
`reserved_successor_attempt_number IS NULL OR reserved_successor_attempt_number = created_attempt_count + 1`;
`(outcome = 'ALLOWED' AND predecessor_terminal_state = 'UNAVAILABLE') = (availability_observation_id IS NOT NULL)`.
Indexes: partial `(retry_not_before_utc) WHERE outcome = 'ALLOWED'` (the
pending-not-before index), `experiment_id`, `primary_terminal_diagnostic_id`.
Trigger T-APPEND-ONLY. The precedence-consistency filter over the gates is the
record validator's (runs on egress).

#### 3.3.7 `runtime_availability_observations` (owning task 3)

`availability_observation_id TEXT PK` (E1, `avail_`, 42; the parent of the
`engine_runs` and `retry_decisions` keys). The other thirteen fields map with
E1/E2/E3/E5 (`operating_system` `OperatingSystem`; `reason_code` N1); plus
`content_sha256 TEXT NOT NULL`, a
persistence-owned integrity fingerprint `sha256_bytes(canonical_json_bytes(record.model_dump(mode="json")))`
(not a canonical hashing profile; declared reading for the spec's "immutable
content hash"). CHECKs: `(available = 0) = (reason_code IS NOT NULL)`;
`expires_at_utc > observed_at_utc`. Indexes: `(adapter_name, adapter_version,
executable_hash, availability_observation_id)` (the `list_for_adapter` order),
`(adapter_name, adapter_version, available, observed_at_utc, expires_at_utc)`.
Trigger T-APPEND-ONLY. Restricted delete while referenced: the two foreign keys
from `engine_runs` and `retry_decisions`.

#### 3.3.8 `diagnostics` (owning task 3)

Columns map the fifteen fields: `diagnostic_id` PK (`diag_`), `schema_version`,
`severity` (E2), `error_code` (TEXT 3..128), `category` (E2), `message` (TEXT
1..1024), `source_component` (E1), `experiment_id`/`run_id`/`invocation_id`/`engine`
(N1, indexed, **no foreign key**, §1.4 row 1), `retriable` (E3), `timestamp_utc`
(E5), `details` (E7, CHECK `length(CAST(details AS BLOB)) <= 16384` — a byte
count, matching `MAX_DETAIL_BYTES` over UTF-8), `causal_diagnostic_ids`
(E8, bound 32; the canonical reconstruction source of the `diagnostic_causes`
relation, §3.3.9, reading 23). CHECKs: `run_id IS NULL OR experiment_id IS NOT NULL`;
`category NOT IN ('ENGINE_RUNTIME','PROTOCOL','TIMEOUT','CANCELLATION') OR invocation_id IS NOT NULL`.
Indexes: `error_code`, `category`, `severity`, `experiment_id`, `run_id`,
`invocation_id`, `timestamp_utc`. Trigger T-APPEND-ONLY. The recorder's
idempotence (§4.4) is an `INSERT … ON CONFLICT (diagnostic_id) DO NOTHING`
followed by a read-back of the stored row and by the two edge statements of
§3.3.9.

#### 3.3.9 `diagnostic_causes` (owning task 3; the restricted causal-edge relation)

| Column | Type / encoding | Source | NULL |
|---|---|---|---|
| `diagnostic_id` | TEXT FK → `diagnostics` RESTRICT; PK part 1 | the referring diagnostic | no |
| `causal_diagnostic_id` | TEXT FK → `diagnostics` RESTRICT; PK part 2 | one member of the referrer's `causal_diagnostic_ids` | no |

Constraints: `PRIMARY KEY (diagnostic_id, causal_diagnostic_id)`; CHECK
`diagnostic_id <> causal_diagnostic_id` (the record refuses a self-cause; the
relation repeats it). Index: `causal_diagnostic_id` (the reverse lookup "what
cites this diagnostic"). Trigger T-APPEND-ONLY. Both foreign keys are
`RESTRICT`, so an edge row exists only while both endpoints exist and neither
endpoint can be deleted while the edge exists (spec 23.3.1 "separate restricted
join table"; no deletion path exists in Stage 8 anyway, T-APPEND-ONLY on
`diagnostics`).

Writer and derivation (reading 23): exactly one writer,
`SqliteDiagnosticRecorder.record`, inside the same autonomous transaction as
the diagnostic row and immediately after its read-back, issues two set-based
statements that read the stored JSON column and never a Python attribute:

- forward edges — `INSERT INTO diagnostic_causes (diagnostic_id, causal_diagnostic_id) SELECT :id, j.value FROM diagnostics d, json_each(d.causal_diagnostic_ids) j WHERE d.diagnostic_id = :id AND j.value IN (SELECT diagnostic_id FROM diagnostics) ON CONFLICT DO NOTHING`;
- back edges — `INSERT INTO diagnostic_causes (diagnostic_id, causal_diagnostic_id) SELECT d.diagnostic_id, :id FROM diagnostics d, json_each(d.causal_diagnostic_ids) j WHERE j.value = :id ON CONFLICT DO NOTHING`.

Both run on every `record` call, including the idempotent replay of an
already-stored diagnostic, so the relation converges regardless of recording
order: a primary recorded before the additionals it cites (the Stage 7
`_record_all` order) gets its edges when each additional is recorded. A refusal
of either statement (a foreign-key or CHECK failure would be a defect, since
the statements select only existing endpoints) rolls the whole `record`
transaction back — the diagnostic row is not committed without its edges. The
relation is never read to rebuild a `Diagnostic` (the E8 column is the
source); it exists as the restricted, indexable home of the same edges.
Consistency between the two representations is a measured invariant:
`consistency_report().causal_edge_mismatches` (§4.6) is zero after every
completed batch, and `unresolved_causal_references` counts JSON causes with no
row yet.

#### 3.3.10 `strategy_versions` (owning task 3)

`content_hash TEXT PK`; `strategy_version_id TEXT UNIQUE` (`strv_`); `strategy_id`
(`strat_`); `schema_version`; `record` E7 (the whole `StrategyVersion`, whose
`validate_identity_is_recomputed` re-derives `content_hash` and every extension
hash on egress); `hashing_profile_version TEXT CHECK (= 'strategy-version/v1')`;
`created_at_utc` E5; UNIQUE `(strategy_id, created_at_utc)` (spec 23.3.1; two
valid versions of one strategy at one instant collide on it, which `register`
reports as `CORE.INVARIANT_VIOLATION` after a pre-insert read, reading 12).
Trigger T-APPEND-ONLY. Deletion restricted while an experiment references the
hash: the application rule of §3.3.1 (no foreign key from `experiments`), and no
delete path exists for this table.

#### 3.3.11 `datasets` and `dataset_partitions` (owning task 3)

`datasets`: `dataset_id TEXT PK` (`ds_`); `content_hash TEXT UNIQUE`;
`schema_version`; `record` E7 (the `DatasetDescriptor`); typed projections for
the spec's index — `venue` (E1), `instrument_canonical_id` (E1),
`data_type` (E2 `DatasetDataType`), `timeframe` (TEXT, N1), `start_utc`/`end_utc`
(E5, CHECK `start_utc < end_utc`), `validation_status` (E2), `created_at_utc`.
Index `(instrument_canonical_id, data_type, start_utc, end_utc)`.
`dataset_partitions`: `partition_id TEXT PK` (`part_`); `dataset_id` FK →
`datasets` RESTRICT; `ordinal` E4 `>= 0`; UNIQUE `(dataset_id, ordinal)`;
`record` E7 (the `DatasetPartition`); projections `content_hash`,
`raw_checksum`, `normalized_checksum` (E1 hash, indexed), `relative_path`,
`row_count`, `start_utc`, `end_utc`. Both T-APPEND-ONLY. `register(descriptor,
partitions)` validates `validate_dataset_identity(descriptor, partitions)` before
any statement and inserts descriptor and partitions in one transaction; an
identical content hash already registered is an idempotent no-op; a different
descriptor under the same hash is `CORE.INVARIANT_VIOLATION`.

#### 3.3.12 `artifact_owners` (owning task 3)

`owner_hash TEXT PK` (E1 hash, `artifact_owner_hash(owner)`); `owner_kind` (E2
over the six literals); nullable TEXT columns `experiment_id`, `run_id`,
`invocation_id`, `dataset_id`, `strategy_version_id`, `strategy_version_hash`,
`adapter_name`, `adapter_version`, `engine_name`, `engine_version`,
`core_component`, `correlation_id`. Foreign keys (all RESTRICT; SQLite does not
enforce a foreign key whose child columns are `NULL`, which is exactly the
variant semantics): `experiment_id` → `experiments`; `(experiment_id, run_id)` →
`engine_runs(experiment_id, run_id)`; `(run_id, invocation_id)` →
`command_invocations(run_id, invocation_id)`; `dataset_id` → `datasets`;
`strategy_version_id` → `strategy_versions(strategy_version_id)`;
`strategy_version_hash` → `strategy_versions(content_hash)`. One CHECK per
variant, exactly-one-variant (the required columns `NOT NULL`, every other
column `NULL`): `RUN` → `experiment_id`, `run_id` non-null, `invocation_id`
either, the other nine null; `EXPERIMENT` → `experiment_id` alone; `DATASET` →
`dataset_id` alone; `STRATEGY` → exactly one of `strategy_version_id`,
`strategy_version_hash`, all else null; `ADAPTER` → `adapter_name`,
`adapter_version` non-null, `(engine_name IS NULL) = (engine_version IS NULL)`,
all else null; `SYSTEM` → `core_component`, `correlation_id` alone. Indexes:
`(owner_kind, experiment_id)`, `(owner_kind, run_id)`, `dataset_id`,
`strategy_version_hash`, `(adapter_name, adapter_version)`. Trigger
T-APPEND-ONLY. `register(owner)` is idempotent on `owner_hash`; egress rebuilds
the variant through `ARTIFACT_OWNER_ADAPTER.validate_json`. Stage 9's
`candidate_artifacts` and `artifact_refs` reference `owner_hash`; the RUN-variant
foreign keys give the specification's "the run must belong to the experiment"
and "`invocation_id` when the candidate belongs to a command" at the SQL level.

#### 3.3.13 `alembic_version`

Alembic's own single-row table; created and maintained only by the runner
(§6.4). Its presence with an unknown identifier is `UNKNOWN`; its absence beside
user tables is `UNVERSIONED`.

### 3.4 Triggers (created by the baseline revision, asserted by Task 2)

| Trigger | Table | Fires | Effect |
|---|---|---|---|
| T-EXP-TERMINAL | `experiments` | `BEFORE UPDATE` when `OLD.state IN ('COMPLETED','COMPLETED_WITH_WARNINGS','FAILED','CANCELLED')` | `RAISE(ABORT, 'terminal experiment is immutable')` |
| T-EXP-FROZEN | `experiments` | `BEFORE UPDATE OF spec, spec_hash, strategy_version_hash, dataset_version_hash` when `OLD.state NOT IN ('DRAFT','VALIDATED')` and any of the four differs from `OLD` | `RAISE(ABORT, 'experiment spec is frozen at QUEUED')` |
| T-EXP-QUEUE-SNAPSHOT | `experiments` | `BEFORE UPDATE OF state` when `NEW.state = 'QUEUED' AND OLD.state <> 'QUEUED' AND NEW.configuration_snapshot_json IS NULL` | `RAISE(ABORT, 'experiment cannot be queued without a frozen configuration snapshot')` (reading 22; the repository guard of §4.3.1 step d′ refuses first) |
| T-EXP-SNAPSHOT-FROZEN | `experiments` | `BEFORE UPDATE OF configuration_snapshot_schema_version, configuration_snapshot_json, configuration_audit_hash, material_base_configuration_hash` when `OLD.configuration_snapshot_json IS NOT NULL` and either `NEW.configuration_snapshot_json IS NULL` (clearing, at any state) or `OLD.state NOT IN ('DRAFT','VALIDATED')` and any of the four differs from `OLD` | `RAISE(ABORT, 'configuration snapshot is frozen at QUEUED')` — a snapshot may be replaced only while the experiment is `DRAFT`/`VALIDATED` and is never cleared |
| T-RUN-TERMINAL | `engine_runs` | `BEFORE UPDATE` when `OLD.state IN (the seven terminals)` | `RAISE(ABORT, 'terminal engine run is immutable')` (the port: a terminal run accepts no CAS at all) |
| T-INV-TERMINAL | `command_invocations` | `BEFORE UPDATE OF state` when `OLD.state IN (the five terminals)` and `NEW.state <> OLD.state` | `RAISE(ABORT, 'terminal invocation state is immutable')`; same-state enrichment passes |
| T-APPEND-ONLY (one per table) | `run_events`, `retry_decisions`, `runtime_availability_observations`, `diagnostics`, `diagnostic_causes`, `strategy_versions`, `datasets`, `dataset_partitions`, `artifact_owners` | `BEFORE UPDATE` and `BEFORE DELETE` | `RAISE(ABORT, '<table> is append-only')` |
| T-NO-DELETE (one per table) | `experiments`, `engine_runs`, `command_invocations` | `BEFORE DELETE` | `RAISE(ABORT, '<table> rows are never deleted')` (spec 23.3.1: no relational cascade may erase history) |

A trigger abort surfaces as `SQLITE_CONSTRAINT_TRIGGER` and maps to
`CORE.INVARIANT_VIOLATION` (reading 3); the application predicates refuse the
same writes first, so a trigger firing in production is itself a defect report.
Triggers and CHECK expressions are invisible to Alembic's metadata comparison;
Task 2's `sqlite_master` assertions pin their exact SQL text.

### 3.5 Invariant → enforcing layer

| Invariant (spec) | Record validator | Application operation (Stage 5–7, unchanged) | Repository / codec (Stage 8) | SQL (Stage 8) |
|---|---|---|---|---|
| Unique operational identifiers | — | — | duplicate insert → `PERSISTENCE.CONCURRENCY_CONFLICT` | PRIMARY KEY |
| Unique `(experiment_id, logical_slot_id, attempt_number)`; `(invocation_id, sequence)`; `event_id`; `(logical_slot_id, predecessor_run_id)` | — | replay/divergence classification after a read | conflict mapping | UNIQUE / PK |
| Slot identity scoped by experiment; a run belongs to a slot of its own experiment (reading 7) | `ExperimentSpec` unique slot ids per spec | `create_attempt`/`create_successor` check the slot is in the spec | `engine_slots` written from the spec | `engine_slots` PK `(experiment_id, logical_slot_id)`; composite FK from `engine_runs` and `retry_decisions` |
| One open invocation per run and kind; one active attempt per slot | — | `create_invocation`, `create_attempt`/`create_successor` | — | partial UNIQUE INDEX |
| Invocation-to-run agreement; event-to-invocation-to-run agreement | `RunEvent.run_id` vs ledger | `create_invocation` parent matrix, ledger identity | — | composite FKs |
| Revision compare-and-swap: a missing row or a stored revision other than the expected one is a conflict; zero rows = conflict | — | expected revision from the read set | §4.3.1 steps a–c: the pre-read inside the transaction decides missing → `PERSISTENCE.CONCURRENCY_CONFLICT`, stale → `PERSISTENCE.CONCURRENCY_CONFLICT`; step e–f: `UPDATE … WHERE <identity> = ? AND revision = ?`, rowcount 0 or a refused write promotion → `PERSISTENCE.CONCURRENCY_CONFLICT` | — |
| Replacement revision = expected + 1 | `assert_*_transition` pair rules | — | `CORE.INVARIANT_VIOLATION` at §4.3.1 step d — after the pre-read has matched the stored revision, before the `UPDATE`, with no mutating statement issued | — |
| The `experiments` row owns the frozen configuration snapshot (spec 22.2, 23.3.1) | `ConfigSnapshot` re-derives both hashes and re-validates the JSON | `queue_experiment` proves the request's hash and derived policy (`assert_queue_freeze`) | §4.3.1 step d′: the `VALIDATED → QUEUED` swap requires a frozen snapshot agreeing with the frozen spec; `freeze` refuses at/after `QUEUED`; `get` rebuilds through the validator | whole-or-absent CHECK; T-EXP-QUEUE-SNAPSHOT; T-EXP-SNAPSHOT-FROZEN |
| Causal edges live in a separate restricted relation (spec 23.3.1) | `causal_diagnostic_ids` sorted, bounded, no self-cause | the lifecycle records referrers and referents in one batch | the recorder derives `diagnostic_causes` from the stored JSON in the diagnostic's transaction; `causal_edge_mismatches` measures agreement | PK, two `RESTRICT` keys, CHECK no self-edge, T-APPEND-ONLY |
| State-governed presence (15.2 table, run and decision shapes) | yes | yes | egress re-validation | CHECK over `NULL`-ness |
| `deadline_utc = launch + timeout`; exit value → category | yes | yes | — | CHECK arithmetic / CASE |
| Terminal immutability | `assert_terminal_*_immutability` | yes | experiment CAS spec guard | triggers T-*-TERMINAL |
| Frozen spec and retry-policy bytes at `QUEUED` | `assert_queue_freeze` | `queue_experiment`, `replace_experiment_spec` | `spec_hash` guard on CAS | T-EXP-FROZEN |
| Append-only facts, no cascade erasure | — | no delete path | no `DELETE` except the `engine_slots` projection rewrite (§4.3) | T-APPEND-ONLY, T-NO-DELETE, RESTRICT |
| Projection columns agree with their E7 snapshot (N6) | — | — | same-statement write; `consistency_report()` projection rows; §7.3 property | T-EXP-FROZEN (experiments) |
| Sorted unique identifier tuples; primary ∈ `diagnostic_ids`; details bounds | yes | yes | egress re-validation | array-length CHECK only |
| Owner exactly-one-variant | discriminated union | Stage 9 | egress through `ARTIFACT_OWNER_ADAPTER` | per-variant CHECK + FKs |
| Raw token never persisted | four reviewed carriers only | Stage 6 redaction | no `AttemptToken` annotation in persistence | no column |
| Decimal never binary float; UTC never naive | yes | yes | E5/E6 | TEXT / INTEGER types |
| Referenced diagnostic exists | — | three read-before-CAS sites | `dangling_diagnostic_references()` query (§4.6) | index only (§1.4) |
| Referenced observation exists | — | `evaluate_retry` reads it | FK failure → `CORE.INVARIANT_VIOLATION` | FK RESTRICT |

---

## 4. Port and transaction contracts (matrix B)

### 4.1 The consuming operations (existing, unchanged)

Every application operation keeps its reads, writes, revisions and failure
codes exactly as committed; Stage 8 changes what lies behind the ports, not
what the operations do. The table is the flow matrix Task 7 composes and Tasks
4–6 test through the ports (operations from `crypto_lab.experiments.*`;
`LostSwap` → `run_operation` reruns the whole operation once over a fresh
transaction, then returns the second loss as the public `Failure`).

| Operation (module) | Reads (port methods) | Writes | Must commit together | On a lost write |
|---|---|---|---|---|
| `create_experiment` (`experiment_service`) | none | `experiments.add` | one row (+ `engine_slots` projection rows, one statement group) | the `add` `Failure` is returned directly |
| `replace_experiment_spec`, `transition_experiment`, `queue_experiment`, `cancel_experiment` (`experiment_service`) | `experiments.get` | `experiments.compare_and_swap` (+ slot projection replace for a pre-`QUEUED` spec change) | one row | `LostSwap`; after reload: terminal → `CORE.INVARIANT_VIOLATION`, replay at matching revision → `Success`, moved → `PERSISTENCE.CONCURRENCY_CONFLICT` |
| `create_attempt` (`run_service`) | `experiments.get`, `engine_runs.latest_attempt`, `engine_runs.get_by_attempt_number` | `engine_runs.add_attempt` **and** `experiments.compare_and_swap` (`QUEUED → RUNNING` or revision bump) | both, or neither | `LostSwap`; identical replay → `Success`, cancelled → invariant |
| `transition_run` (`run_service`) | `engine_runs.get` | `engine_runs.compare_and_swap` | one row | `LostSwap` |
| `create_invocation` (`invocation_service`) | `engine_runs.get`, `experiments.get`, `engine_runs.latest_attempt`, `command_invocations.list_for_run` (VALIDATE then same kind) | `command_invocations.add` | one row | linked path `LostSwap`; DESCRIBE path returns the `add` `Failure` |
| `transition_invocation`, `enrich_invocation` (`invocation_service`) | `command_invocations.get`; `diagnostics.get` for an unrecognized `EXITED` primary | `command_invocations.compare_and_swap` | one row | `LostSwap` |
| `begin_linked_launch`, `start_linked_run`, `transition_invocation_and_run` (`invocation_service`) | invocation, run; `diagnostics.get` for a `FAILED_TO_START` primary | `command_invocations.compare_and_swap` then `engine_runs.compare_and_swap` | both, or neither | `LostSwap` |
| `evaluate_retry` (`retry`) | `retry_decisions.get_by_predecessor`, `experiments.get`, `engine_runs.get`, `latest_attempt`, `count_attempts`, `diagnostics.get`/`get_many` (closure), `availability_observations.get`/`list_for_adapter` | `ALLOWED`: `experiments.compare_and_swap` then `retry_decisions.insert_if_absent`; `DENIED`: `insert_if_absent` only | both, or neither | `LostSwap`; the reload replays the durable row (§5.1 C-8) |
| `create_successor` (`retry`) | decision, experiment, predecessor, `get_by_attempt_number(reserved)` | `engine_runs.add_attempt` **and** `experiments.compare_and_swap` (revision bump) | both, or neither | `LostSwap`; identical successor replays, divergent → conflict |
| `aggregate_experiment` (`aggregation`) | `experiments.get`, per slot `latest_attempt`, `retry_decisions.get_by_predecessor` | `experiments.compare_and_swap` | one row | `LostSwap`; now-terminal → idempotent verdict |
| `apply_command_semantic_outcome` (`semantic_outcome`) | invocation, run, experiment, `list_for_run` (both linked kinds), `latest_attempt` | `engine_runs.compare_and_swap` then `command_invocations.compare_and_swap` (ids-only enrichment) | both, or neither | `LostSwap`; caller obligation: record `reconciliation.diagnostics` after `Success` (§1.4) |
| `Stage5InvocationLifecycle.load`, `linked_run`, `request_envelope` | read-only transaction (`begin` → reads → `rollback`) | none | — | — |
| `Stage5InvocationLifecycle.begin_start`, `record_process_start`, `record_terminal`, `enrich`, `resolve_external_winner` | a read-only transaction, then `DiagnosticRecorder.record` for every referenced diagnostic (primary first, additionals in order), then the merged operation's own `run_operation` transaction | as the merged operation | as the merged operation | the operation's `Failure` is returned unchanged |
| `Stage5InvocationLifecycle.append_event` | — | `engine_runs.append_event` then `commit()` in one transaction | one row | the `Failure` (append or commit) is returned verbatim to the supervisor; no retry |
| `reconcile_invocations` (`process_supervision.reconciliation`) | `ReconciliationSource.list_reconciliation_targets` once per pass, `run_facts` per linked non-`PENDING` record | through the lifecycle port only | — | — |

What is held inside any transaction: in-memory work, `Clock.now_utc()` reads and
`IdentitySource` draws. No operation performs I/O, launches a process, hashes a
file or calls another operation inside a transaction (spec 8.2, 23.2); Task 7's
composition test asserts, through a counting unit of work, that no transaction is
open while the supervisor awaits the child.

### 4.2 The unit of work

`SqliteUnitOfWork(database: SqliteDatabase, clock: Clock)` is the root;
`begin()` returns a `SqliteTransaction`. Both satisfy `UnitOfWork` structurally;
the transaction additionally exposes the persistence-owned members
`availability_observation_writer`, `configuration_snapshots`, `artifact_owners`,
`strategy_versions` and `datasets` (readings 11, 12, 22).

| Step | Behaviour | Failure surface |
|---|---|---|
| `begin()` on the root | checks out one pooled DBAPI connection (PRAGMAs already applied and read back on physical connect, §6.1), issues `BEGIN` (deferred), binds the six port repositories and the five extras to the connection, returns the transaction | a connection that cannot be checked out (a DBAPI error, or the pool's own checkout-timeout error, which is not a DBAPI error and has its own branch) or whose `BEGIN` fails leaves the transaction **closed** with `PERSISTENCE.STORAGE_UNAVAILABLE`: every member call and `commit()` return it; `rollback()` releases whatever was acquired |
| `begin()` on a transaction, any member on the root, any member or `commit()` after close | `RuntimeError` (programmer defect, reading 2) | — |
| first read | establishes the WAL snapshot for the transaction; every later read is repeatable and sees the transaction's own writes | — |
| a repository write | the statement runs on the owned connection the moment the method issues it (Core statements; no session, no identity map, no deferred flush — nothing is written that the method did not issue at that point); a compare-and-swap first performs its read-only checks of §4.3.1 and issues its `UPDATE` only after they pass; a rowcount-0 CAS, `SQLITE_BUSY`, `SQLITE_BUSY_SNAPSHOT`, `SQLITE_CONSTRAINT_UNIQUE`/`PRIMARYKEY` → `PERSISTENCE.CONCURRENCY_CONFLICT`; `SQLITE_CONSTRAINT_FOREIGNKEY`/`CHECK`/`TRIGGER`/`NOTNULL` → `CORE.INVARIANT_VIOLATION`; `SQLITE_FULL`, `SQLITE_IOERR*`, `SQLITE_NOMEM`, `SQLITE_READONLY*` → `PERSISTENCE.WRITE_FAILED`; `SQLITE_CORRUPT`, `SQLITE_NOTADB` → `PERSISTENCE.STORAGE_UNAVAILABLE` | the `Failure` is returned by that call; for the conflict and invariant classes the refused statement alone is aborted and the transaction **stays usable** (later reads and writes proceed on their own merits and `commit()` publishes whatever succeeded — the shared contract cases depend on this); a method that issues several statements (`ExperimentRepository.add`, the slot-rewriting `compare_and_swap`, `SqliteDatasetRepository.register`) wraps them in one `SAVEPOINT` — entered only after the method's read-only refusals have passed, so a refused replacement opens no savepoint — and, on any refusal, rolls back **to that savepoint** before returning, so none of the method's earlier statements stays staged (reading 21, C-29); for the I/O class the transaction is **closed**: every later member call and `commit()` return the stored `Failure` and only `rollback()` releases it |
| `commit()` | closed → returns the stored `Failure` after releasing; otherwise `COMMIT`; `SQLITE_BUSY` at commit (WAL: only a checkpoint race) → `PERSISTENCE.CONCURRENCY_CONFLICT` after rollback; I/O → `PERSISTENCE.WRITE_FAILED` after rollback; success → `Success(None)`; the connection returns to the pool. Over SQLite `commit()` never reports a revision or unique-key loss (those surface at the write) | as listed |
| `rollback()` | idempotent; consults the DBAPI connection's `in_transaction` (an I/O error may already have ended the SQLite transaction) and issues `ROLLBACK` only when one is open; returns the connection; a no-op after `commit()` or a second call | never raises for a closed transaction |
| an unfinished transaction that is simply dropped | not relied upon: the pool's finalizer eventually rolls back and reclaims the connection, but a reference cycle can delay it until the cyclic collector runs; `SqliteUnitOfWork` keeps a weak set of its open transactions and the test harness rolls back every survivor at teardown (§7.1); Task 4's probe validates the reclaim path | — |

Connection lifetime: one DBAPI connection per open transaction, exclusively
owned; returned to the pool at `commit()`/`rollback()`; a pooled connection may
serve another thread later (the DBAPI thread check is disabled for that reason
and PRAGMAs are re-verified only on physical connect). Nothing holds a
connection outside a transaction. The pool size is bounded (proposed 8 + 2
overflow, matching `scheduler.max_concurrent_runs` ≤ 8 supervisors plus the
reconciler and the CLI); exhaustion waits then fails as
`PERSISTENCE.STORAGE_UNAVAILABLE`, never hangs. The exact pool class and
argument names are confirmed by Task 1's probes (§2.8).

Read-only sessions (`SqliteDatabase.read_only()`): a deferred `BEGIN`, reads,
`ROLLBACK`; used by `SqliteReconciliationSource` and by test helpers; never
takes the writer lock and never blocks a writer (WAL).

### 4.3 Repository method contracts

Every method: exact port signature (§2.2); statements are Core constructs over
`schema.py`; every `Failure` carries one diagnostic from
`persistence/diagnostics.py` stamped with the injected clock; "live" reads are
the transaction's snapshot plus its own writes (§4.2).

| Method | Reads | Writes / statement shape | Success value | Failure codes and conditions |
|---|---|---|---|---|
| `ExperimentRepository.get` | `SELECT … WHERE experiment_id = ?` | — | the decoded `ExperimentRecord` | INV: no row (`… does not exist`); INV: egress validation error |
| `ExperimentRepository.add` | — | `SAVEPOINT`; `INSERT experiments`; `INSERT engine_slots` × slots (each row `(experiment_id, logical_slot_id, …)` from the record); `RELEASE` — on any refusal `ROLLBACK TO` the savepoint, then return | `None` | CONF: `experiment_id` exists (PK); INV: CHECK/FK/trigger (including a slot row refused after the experiment row succeeded — nothing of the method stays staged, C-29); WRITE_FAILED |
| `ExperimentRepository.compare_and_swap` | the stored row, pre-read inside the transaction (§4.3.1 step a: the snapshot plus this transaction's own writes); for the `VALIDATED → QUEUED` edge also the row's four snapshot columns | after steps a–d′ pass: `UPDATE experiments SET <every record column of §3.3.1 — never the four snapshot columns, which only freeze writes> WHERE experiment_id = ? AND revision = ?`; when the stored state is `DRAFT`/`VALIDATED` and `spec_hash` changed the write runs inside a `SAVEPOINT` entered at step e: the `UPDATE`, `DELETE engine_slots WHERE experiment_id = ?`, the reinserts, `RELEASE` — any refusal rolls back to the savepoint | the replacement itself (the values the `UPDATE` wrote; no re-read, §4.3.1 g) | in the order of §4.3.1: CONF: no stored row (b); CONF: stored revision ≠ expected (c); INV: `replacement.revision != expected + 1` (d); INV: stored state at/after `QUEUED` and `spec_hash` differs, or the `VALIDATED → QUEUED` edge with no frozen snapshot or a snapshot disagreeing with `replacement.spec` (d′) — none of b–d′ writes; CONF: rowcount 0 or a refused write promotion at the `UPDATE` (f); INV: CHECK/trigger (a refused slot reinsert leaves the stored experiment and its slots untouched, C-29) |
| `EngineRunRepository.get` | by `run_id` | — | `EngineRunRecord` | INV: missing / egress |
| `EngineRunRepository.add_attempt` | — | `INSERT engine_runs` | `None` | CONF: PK or `(experiment_id, logical_slot_id, attempt_number)` or active-attempt partial index; INV: FK (`experiment_id`, slot, predecessor, observation) or CHECK |
| `EngineRunRepository.compare_and_swap` | the stored row by `run_id`, pre-read inside the transaction (§4.3.1 step a) | after steps a–d pass: `UPDATE … WHERE run_id = ? AND revision = ?` | the replacement | in the order of §4.3.1: CONF: no stored row (b); CONF: stored revision ≠ expected (c); INV: revision step (d), nothing written; CONF: rowcount 0 or a refused write promotion (f); INV: CHECK/FK/trigger at the `UPDATE` (a terminal stored row fires T-RUN-TERMINAL) |
| `EngineRunRepository.count_attempts` | `SELECT count(*) WHERE experiment_id = ? AND logical_slot_id = ?` | — | `int` | none beyond storage faults |
| `EngineRunRepository.latest_attempt` | `SELECT … ORDER BY attempt_number DESC LIMIT 1` | — | record or `MISSING` | INV: egress |
| `EngineRunRepository.get_by_attempt_number` | by the unique triple | — | record or `MISSING` | INV: egress |
| `EngineRunRepository.append_event` | `SELECT … WHERE invocation_id = ? AND sequence = ?`; `SELECT … WHERE event_id = ?` | `INSERT run_events` when absent | the stored event (existing identical row, or the inserted one) | CONF: key exists with another `content_hash`; CONF: `event_id` exists under another key; CONF: concurrent insert lost (UNIQUE/PK or snapshot); INV: composite FK (invocation not of that run, DESCRIBE invocation, missing invocation) |
| `EngineRunRepository.list_events` | `SELECT … WHERE invocation_id = ? ORDER BY sequence` | — | tuple, possibly empty | INV: egress |
| `CommandInvocationRepository.get` | by `invocation_id` | — | record | INV |
| `CommandInvocationRepository.add` | — | `INSERT command_invocations` | `None` | CONF: PK or open `(run_id, command_kind)` partial index; INV: FK/CHECK |
| `CommandInvocationRepository.compare_and_swap` | the stored row by `invocation_id`, pre-read inside the transaction (§4.3.1 step a) | after steps a–d pass: `UPDATE … WHERE invocation_id = ? AND revision = ?` | the replacement | in the order of §4.3.1: CONF: no stored row (b); CONF: stored revision ≠ expected (c); INV: revision step (d), nothing written; CONF: rowcount 0 or a refused write promotion (f); INV: CHECK (state row), trigger (terminal state change) at the `UPDATE` |
| `CommandInvocationRepository.list_for_run` | `SELECT … WHERE run_id = ? AND command_kind = ? ORDER BY created_at_utc, invocation_id` | — | tuple | INV: egress |
| `RetryDecisionRepository.get_by_predecessor` | by the composite PK | — | record | INV: missing |
| `RetryDecisionRepository.insert_if_absent` | `SELECT … WHERE logical_slot_id = ? AND predecessor_run_id = ?` | `INSERT retry_decisions` when absent | `RetryDecisionInsertOutcome(inserted=False, record=stored)` when the row was visible; `(inserted=True, record=candidate)` after a successful insert | CONF: the insert lost to a row committed after the snapshot (`SQLITE_BUSY_SNAPSHOT` or PK); INV: FK (`experiment_id`, predecessor, slot, observation) or CHECK |
| `RuntimeAvailabilityObservationReader.get` | by id | — | record | INV |
| `RuntimeAvailabilityObservationReader.list_for_adapter` | `WHERE adapter_name = ? AND adapter_version = ? AND executable_hash = ? ORDER BY availability_observation_id` | — | tuple (unbounded) | INV: egress |
| `DiagnosticReader.get` | by id | — | record | INV |
| `DiagnosticReader.get_many` | `WHERE diagnostic_id IN (…) ORDER BY diagnostic_id` | — | tuple sorted by id | INV: duplicate identifiers or more than 256 requested (before any statement); INV: any identifier missing (names the first missing in request order) |

Every decoded record is re-validated (reading 10); the repository never returns
a row it could not validate. The repositories never read the injected clock
except to stamp their own `Failure` diagnostics, so the operations' pinned
clock-read counts hold.

#### 4.3.1 Compare-and-swap precedence (single authority for the three repositories)

`ExperimentRepository.compare_and_swap`, `EngineRunRepository.compare_and_swap`
and `CommandInvocationRepository.compare_and_swap` evaluate the following
steps in this order and stop at the first refusal. The order is the in-memory
double's `_compare_and_swap` order (reading 5) and the one the retained
contract assertions require.

- **a. Pre-read.** `SELECT … FROM <table> WHERE <identity> = ?` on the
  transaction's own connection, where the identity is the replacement's
  (`experiment_id`, `run_id`, `invocation_id`). The read returns the
  transaction's current view: its WAL snapshot **plus every write this
  transaction has itself issued** — a row it inserted with `add`/`add_attempt`
  or advanced with an earlier swap is read back as written (single-connection
  read-your-writes; no flush is needed because Core statements execute when
  issued). The pre-read is a permitted read, not a mutation.
- **b. No row → `PERSISTENCE.CONCURRENCY_CONFLICT`** (message `… does not
  exist for compare-and-swap`; the zero-row vocabulary of spec 23.2, not the
  `get` miss).
- **c. `stored.revision != expected_revision` → `PERSISTENCE.CONCURRENCY_CONFLICT`**
  (the row moved, or the caller's revision is stale). This is decided before
  any inspection of the replacement.
- **d. `replacement.revision != expected_revision + 1` → `CORE.INVARIANT_VIOLATION`**
  (the persistence CHECK analogue of the double: a programming error, decided
  only for a stored row at the expected revision).
- **d′. Experiments only.** Stored state at or after `QUEUED` and
  `replacement.spec_hash != stored.spec_hash` → `CORE.INVARIANT_VIOLATION`
  (frozen spec, reading 13). `replacement.state == QUEUED` while
  `stored.state == VALIDATED` (the only edge into `QUEUED`) → the row's
  snapshot columns must be non-`NULL` and must agree with the replacement's
  frozen spec: `experiment_configuration_hash(replacement.spec, material_base_configuration_hash) == replacement.spec.configuration_hash`
  and `retry_policy_from_config(ApplicationConfig.model_validate_json(configuration_snapshot_json).scheduler.retry) == replacement.spec.retry_policy`;
  otherwise `CORE.INVARIANT_VIOLATION` (reading 22; T-EXP-QUEUE-SNAPSHOT is the
  SQL-layer second line).
- **e. Conditional `UPDATE`.** `UPDATE <table> SET <every record column> WHERE <identity> = ? AND revision = ?`
  with `expected_revision` bound as the predicate. The `SET` list is exactly
  the columns the record's codec encodes — for `experiments` the record
  columns of §3.3.1 and never the four configuration-snapshot columns, which
  only `SqliteConfigurationSnapshotWriter.freeze` writes (a record swap
  therefore preserves the frozen snapshot bytes, spec 23.3.1). The pre-read
  never replaces this predicate: the write proves its own precondition. The
  experiment CAS that rewrites the slot projection enters its `SAVEPOINT` here,
  never before.
- **f. Zero affected rows → `PERSISTENCE.CONCURRENCY_CONFLICT`.** Likewise the
  write-promotion refusal of reading 3 (`SQLITE_BUSY_SNAPSHOT`, 517: another
  connection committed after this transaction's snapshot began) and the busy
  timeout (`SQLITE_BUSY`, 5) at this statement — both produce **no rowcount**,
  because the statement never executed, and both are the same conflict (this is
  the branch C-4, C-5 and C-12 exercise). A constraint or trigger refusal here
  (`T-*-TERMINAL`, a state CHECK, T-EXP-QUEUE-SNAPSHOT) is
  `CORE.INVARIANT_VIOLATION` with the statement aborted, or rolled back to the
  savepoint for the slot rewrite.
- **g. One affected row → provisional success.** The method returns
  `Success(replacement)` (decoded from the written values). Whether it becomes
  durable is the owning unit of work's decision at `commit()`; the repository
  performs no retry of any step, never changes the transaction mode, and never
  re-reads after the `UPDATE` to "confirm" it.

Guarantees that follow: refusals b, c and d (and d′) issue no mutating
statement and open no savepoint, so the target row is unchanged and a `get` in
the same transaction returns the stored row; a refusal at f leaves the row
unchanged as well (an aborted single statement, or a rolled-back savepoint).
Wherever this plan says a refusal happens "before any statement", it means
before any **mutating** statement: the pre-read and transaction-control
statements (`BEGIN`, `SAVEPOINT`) are permitted and the pre-read is required.
No implicit flush exists to reorder any of this: the repositories issue Core
statements on the connection and hold no ORM session.

Walk-throughs of the retained assertions (both harness kinds), each with the
stored row at revision `r`:

| Call | Steps | Result |
|---|---|---|
| `compare_and_swap(r + 1, bump(stored))` (`test_compare_and_swap_succeeds_only_at_the_expected_revision`, `test_run_and_invocation_compare_and_swap_share_the_contract`) | a finds `r`; c: `r != r + 1` | CONF; the row and the candidate unchanged; the following `compare_and_swap(r, …)` in the same transaction succeeds |
| `compare_and_swap(r + 5, _bump_run(stored_run, VALIDATING))` (`test_a_failed_second_write_leaves_the_first_undurable_after_rollback`) | a finds `r = 0`; c: `0 != 5` | CONF at c — never d, although the replacement's revision `1` would also fail `1 != 6`; no `UPDATE` issued; the run row unchanged |
| `compare_and_swap(0, bump(absent))` then `add(stored)`, then `compare_and_swap(r, same_revision)` and `compare_and_swap(r, bump(bump(stored)))` (`test_compare_and_swap_rejects_a_missing_row_and_a_wrong_revision_step`) | first call: b; after the `add`, a reads the transaction's own insert, c passes (`r == r`), d: `r != r + 1` and `r + 2 != r + 1` | CONF, then INV, INV; `get` returns `stored` |
| C-4: T2 `compare_and_swap(r, E₂)` after T1 committed `E₁` at `r + 1` | a returns `E` at `r` from T2's snapshot (T1's commit is invisible to it); c and d pass; e is refused by the snapshot rule | CONF at f with `sqlite_errorcode == 517`, no rowcount |
| C-5 rerun: `transition_experiment` with a stale request after the driver's reload | a returns the moved row at `r + 1` (a fresh transaction, fresh snapshot); c: `r + 1 != r` | CONF (`_stale` is decided by the operation first; the repository order agrees) |

Where the experiment scope of every slot-related lookup comes from (reading 7;
no lookup uses `logical_slot_id` alone):

| Lookup or write | Experiment scope | Statement predicate |
|---|---|---|
| `count_attempts`, `latest_attempt`, `get_by_attempt_number` | the port arguments `experiment_id`, `logical_slot_id` | `WHERE experiment_id = ? AND logical_slot_id = ?` (plus `attempt_number` for the third) |
| `add_attempt` | the record's `experiment_id` and `logical_slot_id` | the composite foreign key `(experiment_id, logical_slot_id) → engine_slots` refuses a slot of another experiment (C-28 C) |
| the `engine_slots` projection rows | the experiment record being written | `(experiment_id, logical_slot_id)` primary key; a second experiment with the same slot identifiers inserts its own rows (C-28 A) |
| `get_by_predecessor`, `insert_if_absent` | none needed: `predecessor_run_id` is a globally unique `run_id`; the composite foreign keys of §3.3.6 pin the decision to the predecessor's experiment and slot | `WHERE logical_slot_id = ? AND predecessor_run_id = ?` |
| the active-attempt partial index | the row's `experiment_id` | `(experiment_id, logical_slot_id) WHERE state IN (nonterminal five)` |
| `list_reconciliation_targets`, `run_facts`, `list_for_run`, `list_events`, `append_event` | none needed: `invocation_id`, `run_id` and `event_id` are globally unique | by those identifiers |
| the consistency queries `slot_identity_mismatches` and `spec_projection_mismatches` (§4.6) | the joined row's own `experiment_id` | `JOIN engine_slots s ON s.experiment_id = r.experiment_id AND s.logical_slot_id = r.logical_slot_id` (for `engine_runs r`); `json_each(e.spec, '$.selected_engine_slots')` joined to `engine_slots` on `(e.experiment_id, value ->> '$.logical_slot_id')` (for `experiments e`) — never on `logical_slot_id` alone, which would pair every experiment sharing the identifier |

### 4.4 Recorder, writers and registries (Task 3)

| Class | Signature | Transaction | Semantics |
|---|---|---|---|
| `SqliteDiagnosticRecorder(database, clock)` (the other classes in this table are constructed as `Sqlite…(connection, clock=…)` over the enclosing transaction's connection; the clock stamps their own `Failure` diagnostics only) | `record(diagnostic) -> Result[None]` (implements `DiagnosticRecorder`) | its own short write transaction per call (`BEGIN` → `INSERT … ON CONFLICT (diagnostic_id) DO NOTHING` → read back → the two `diagnostic_causes` edge statements of §3.3.9 → `COMMIT`) | idempotent on `diagnostic_id`; the first stored instance is kept and an identical or later re-record returns `Success(None)`; a stored row whose decoded record differs from the argument in any field other than `timestamp_utc` is `CORE.INVARIANT_VIOLATION` (a second diagnostic under a reused identity) and the transaction is rolled back before the edge statements run; the edge statements derive the relation from the stored JSON (`json_each`) — forward edges to recorded causes, back edges from recorded referrers — on every call, so the relation converges under the Stage 7 referrer-first order (reading 23); a refused edge statement rolls the diagnostic back with it; committed before the caller's next `begin()` (§1.5 note 3) |
| `SqliteConfigurationSnapshotWriter` (on the transaction, member `configuration_snapshots`) | `freeze(experiment_id, snapshot: ConfigSnapshot) -> Result[None]`; `get(experiment_id) -> Result[ConfigSnapshot \| MISSING]` | the enclosing transaction | `freeze`: pre-reads the row (missing → INV `does not exist`); stored state at/after `QUEUED` with a stored snapshot → INV (frozen) unless the argument equals it field for field (idempotent `Success`); stored state `QUEUED`/`RUNNING` with no stored snapshot (scaffolding only, §3.3.1) or `DRAFT`/`VALIDATED` → `UPDATE experiments SET configuration_snapshot_schema_version = ?, configuration_snapshot_json = ?, configuration_audit_hash = ?, material_base_configuration_hash = ? WHERE experiment_id = ?` (the revision is not touched: the snapshot is not a record field); a **terminal** scaffolding row without a snapshot is refused at that statement by T-EXP-TERMINAL (INV) and no test reaches it; the argument is an already-validated `ConfigSnapshot`, so ingress needs no further check. `get`: `NULL` → `MISSING`; otherwise `ConfigSnapshot.model_validate({the four columns keyed by the record's field names})` — every field comes from the row, none from a literal — whose validator re-parses, re-canonicalizes and re-hashes; a tampered byte is INV (reading 22) |
| `SqliteAvailabilityObservationWriter` (on the transaction) | `add(observation) -> Result[None]` | the enclosing transaction | insert-once; an identical row (same id, same `content_sha256`) is an idempotent `Success`; same id with a different fingerprint is INV; FK-less; used by the harness, Task 7 and Stage 10 |
| `SqliteStrategyVersionRepository` (implements `StrategyVersionRepository`) | `get_by_hash(content_hash)`, `register(version)` | the enclosing transaction | reading 12: identical hash → idempotent `Success`; same hash with a different record, or a second version of the strategy at the same `created_at_utc`, → `CORE.INVARIANT_VIOLATION` from a pre-insert read when the earlier row is visible to the snapshot; a colliding row committed by another connection after the snapshot surfaces instead as reading 3's `PERSISTENCE.CONCURRENCY_CONFLICT` at the insert, whose rerun then reads it |
| `SqliteDatasetRepository` (implements `DatasetRepository`) | `get_by_hash(content_hash)`, `list_partitions(dataset_id)` (ordered by `ordinal`), `register(descriptor, partitions)` | the enclosing transaction | reading 12; `register` runs `validate_dataset_identity` first, then issues its `INSERT datasets` and `INSERT dataset_partitions` × partitions inside one `SAVEPOINT`; a refusal of any partition insert rolls back to the savepoint so no descriptor row stays staged without its partitions (reading 21, C-29) |
| `SqliteArtifactOwnerRegistry` | `register(owner) -> Result[Sha256]`, `get(owner_hash) -> Result[ArtifactOwnerRef]` | the enclosing transaction | idempotent on `owner_hash`; INV on FK failure (the owner names an unpersisted experiment, run, invocation, dataset or strategy version) |

### 4.5 The reconciliation source (Task 5)

`SqliteReconciliationSource(database, clock)` implements `ReconciliationSource`
over a read-only session per call:

- `list_reconciliation_targets()`:
  `SELECT … FROM command_invocations WHERE state IN ('PENDING','STARTING','RUNNING') OR cleanup_complete = 0 ORDER BY created_at_utc, invocation_id`
  (served by the `(state, cleanup_complete, created_at_utc, invocation_id)`
  index; every row decoded; `INV` on a row that fails egress, naming it).
- `run_facts(run_id)`: one `SELECT` joining `engine_runs` and `experiments` on
  `experiment_id`; `INV` (`does not exist`) when the run or its experiment is
  absent — both read from the same snapshot, so a run whose experiment is missing
  is a genuine invariant, never a race artefact.

The source issues no write; Task 5 asserts `total_changes` of the connection is
unchanged across a pass.

### 4.6 Consistency queries (persistence-owned, read-only; Task 3)

`SqliteDatabase.consistency_report()` (added to `database.py` by Task 3, whose
recorder tests are its first consumer; every count is read-only SQL over the
Task 2 schema, so the complete report exists from Task 3 onward and no count is
a placeholder) returns `ConsistencyReport`, a frozen dataclass of the eight
integer counts enumerated below — this list is the single count inventory
every other section references — which the tests and the Stage 10 startup
verification assert to be zero:

- `dangling_diagnostic_references`: rows of `engine_runs`,
  `command_invocations` (primary and every `diagnostic_ids` member via
  `json_each`) and `retry_decisions` whose referenced `diagnostic_id` has no
  `diagnostics` row (§1.4 row 1);
- `slot_identity_mismatches`: `engine_runs` rows whose adapter/engine columns
  differ from their `engine_slots` row, joined on the composite key
  `(experiment_id, logical_slot_id)` (§4.3 scope table; a join on
  `logical_slot_id` alone would pair rows of other experiments);
- `spec_projection_mismatches`: `experiments` rows whose `engine_slots` rows do
  not equal the slots inside `spec` (the spec's `selected_engine_slots` array
  expanded with `json_each` and matched to `engine_slots` on the same composite
  key, in both directions), or whose `strategy_version_hash`/`dataset_version_hash`
  columns differ from the values inside `spec`;
- `queued_without_snapshot`: `experiments` rows with
  `state NOT IN ('DRAFT','VALIDATED','CANCELLED') AND configuration_snapshot_json IS NULL`
  (reading 22; `CANCELLED` is excluded because a cancellation from `DRAFT` or
  `VALIDATED` lawfully has no snapshot). Zero after every production path
  (`queue_experiment` is the only edge into `QUEUED` and §4.3.1 step d′ guards
  it); non-zero exactly for rows that test scaffolding inserted directly at or
  after `QUEUED` through `add` (§3.3.1, §7.1), which is why the contract and
  lifecycle suites assert every other count and Task 7's flows assert this one
  too;
- `causal_edge_mismatches`: the number of `(diagnostic_id, cause)` pairs in
  any recorded row's `causal_diagnostic_ids` whose cause has a `diagnostics`
  row but no `diagnostic_causes` row, plus the number of `diagnostic_causes`
  rows whose pair is absent from the referrer's JSON (reading 23; zero after
  every completed `record` call);
- `unresolved_causal_references`: `(diagnostic_id, cause)` pairs whose cause
  has no `diagnostics` row (informational; zero after every completed batch and
  every integration flow);
- `registry_projection_mismatches`: `strategy_versions`, `datasets` and
  `dataset_partitions` rows whose typed columns differ from their `record`
  snapshot (rule N6);
- `foreign_key_violations`: `PRAGMA foreign_key_check` row count (zero when
  `foreign_keys=ON` held on every connection).

### 4.7 Multi-row atomicity and read-set validation

Every multi-row operation of §4.1 runs inside one `SqliteTransaction`: the two
`UPDATE`s of a linked pair, the `INSERT` plus `UPDATE` of an attempt or
successor creation, the `UPDATE` plus `INSERT` of an `ALLOWED` retry decision,
and the experiment row plus its slot projection are published by one `COMMIT`
or discarded by one `ROLLBACK`; a refused write publishes nothing, and every
operation rolls back on any `Failure` before it could commit a partial pair.
State read during the transaction is validated before a successful commit by
two mechanisms that need no commit-time re-read: (a) every compare-and-swap
carries the revision the operation read, so a row that another transaction
moved is refused — by the pre-read of §4.3.1 step c when the move is visible to
the transaction (a fresh transaction after the driver's reload), or by the
`UPDATE` (step f: the snapshot rule, or rowcount 0) when it is not; (b) the WAL snapshot rule refuses
the transaction's first write when any other transaction committed after the
snapshot began (`SQLITE_BUSY_SNAPSHOT`), so a read set — including rows that
are only read, never written (aggregation's latest attempts, a linked pair's
partner) — cannot have changed underneath a transaction that then publishes.
Both surface as `PERSISTENCE.CONCURRENCY_CONFLICT` and both are exercised by
§5.1. Diagnostics recorded between the lifecycle's read-only transaction and
the operation's transaction are durable before the operation's snapshot begins,
so the three read-before-CAS sites see them.

---

## 5. Concurrency and recovery cases (matrix C)

### 5.1 The case matrix

Every case is constructible over a real temporary database. "T1/T2" are two
`SqliteTransaction`s on two connections; "R" is a raw `sqlite3` connection the
test holds to occupy the writer lock; "P" is a child interpreter. Under the
deferred model (§4.2) almost every interleaving is driven from one test thread
in call order — a stale-snapshot refusal is immediate and a lock wait is bounded
by the configured `busy_timeout_ms` — so no test sleeps to "let the other side
win". `CONF` = `PERSISTENCE.CONCURRENCY_CONFLICT`, `INV` = `CORE.INVARIANT_VIOLATION`.
Test modules live under `tests/unit/persistence/` unless a package is given.

| Id | Case | Interleaving | Winner | Loser result | Durable state | Test | Task |
|---|---|---|---|---|---|---|---|
| C-1 | Concurrent creation, same identity | T1 `experiments.add(E)`, T1 commit; T2 (begun before T1's commit, no read yet) `experiments.add(E')` | T1 | `CONF` at `add` (PK; or `SQLITE_BUSY` if T1 still holds the lock); T2's later `commit()` → `Success` publishing nothing (the refused statement wrote no row) | exactly `E` | `test_sqlite_repositories.py::test_concurrent_creation_of_one_identity_refuses_the_later_writer` | 4 |
| C-2 | Distinct identities, same attempt key | T1 `add_attempt(A: slot S, n=1)` commit; T2, which read the slot (`count_attempts`) before T1's commit, `add_attempt(B: slot S, n=1)` | T1 | `CONF` at `add_attempt` (`SQLITE_BUSY_SNAPSHOT`, code 517, because T2 holds a read snapshot); a T2 that had not read gets `CONF` from the UNIQUE index (2067) instead — both `CONF`, the test asserts the code only in the first shape | `A` only | `…::test_the_attempt_key_refuses_a_second_attempt_one_from_another_connection` | 4 |
| C-3 | Open-invocation partial index | T1 `add(VALIDATE PENDING for run R)` commit; T2 `add(VALIDATE PENDING, other id, run R)`; then T3 `add(VALIDATE EXITED, run R)`; T4/T5 two `DESCRIBE PENDING` | T1; T3, T4, T5 succeed | T2 `CONF` at `add` | one open VALIDATE, one terminal VALIDATE, two DESCRIBEs | `…::test_the_open_invocation_index_holds_across_connections` | 4 |
| C-4 | Revision compare-and-swap race (repository level) | T1 and T2 both `experiments.get(E)` at revision r; T1 `compare_and_swap(r, E₁)` commit; T2 `compare_and_swap(r, E₂)` | T1 | `CONF` at the CAS call: T2's pre-read (§4.3.1 step a) returns `E` at r from its own snapshot, steps b–d pass, and the `UPDATE` is refused by the snapshot rule (`SQLITE_BUSY_SNAPSHOT`, step f, no rowcount); T2 may still read (`get` returns `E` from its snapshot) and its `commit()` publishes nothing; the test rolls it back | `E₁` at r+1 | `…::test_a_moved_row_refuses_the_stale_compare_and_swap_at_the_call` | 4 |
| C-5 | Revision race through the driver | `transition_experiment` on T2 with an `InterleavingUnitOfWork` whose first `experiments.get` lets T1 commit the same edge (or a different edge) | T1 | first attempt lost (`LostSwap`), driver reruns once; the request still carries the stale revision, so the rerun returns `CONF` (`_stale`) for the same edge and for a moved non-terminal row, and `INV` when the stored row is now terminal — exactly two `begin()` calls | one write (T1's) | `test_sqlite_driver_races.py::test_run_operation_reloads_once_after_a_lost_experiment_swap` | 6 |
| C-6 | Linked pair vs partner change | T2 `begin_linked_launch` (invocation `PENDING→STARTING`, run `READY→STARTING`) interleaved with T1 `transition_run(READY→CANCELLED)` committing after T2's reads | T1 | T2's first `UPDATE` refused → `LostSwap`; rerun sees `(PENDING, CANCELLED)` and returns `CORE.INVARIANT_VIOLATION` (`begin_linked_launch` requires a `PENDING` invocation beside a `READY` run); **neither** row partially advanced | invocation `PENDING`, run `CANCELLED` | `test_sqlite_driver_races.py::test_a_linked_launch_loses_atomically_to_a_run_cancellation` | 6 |
| C-7 | Retry decision, divergent concurrent loser replays the durable winner | `evaluate_retry` on T2 through an `InterleavingUnitOfWork` whose hook, after T2's phase-1 `get_by_predecessor` read absence, commits `D₁` (ALLOWED) from another connection; T2's snapshot predates `D₁`; an `UNAVAILABLE` predecessor whose observation expired between the two evaluations (`FixedClock` advanced) makes T2's candidate `D₂ ≠ D₁` | the other connection | T2's `insert_if_absent` is refused (`SQLITE_BUSY_SNAPSHOT` → `CONF` → `LostSwap`); the rerun's phase 1 reads `D₁` and returns `Success(D₁)` by identity — no projection comparison, no `RETRY.DECISION_CONFLICT` (reading 19); exactly two `begin()` calls | `D₁` only; `D₂` never written | `test_sqlite_retry_decisions.py::test_a_divergent_concurrent_decision_replays_the_durable_winner` | 6 |
| C-8 | Retry decision, identical replay after a lost insert | as C-7 with identical inputs | the other connection | rerun returns `Success(D₁)` after exactly two `begin()` calls; the projections are equal, which the test asserts to distinguish it from C-7 | `D₁` only | `…::test_an_identical_concurrent_decision_replays_the_durable_row_once` | 6 |
| C-9 | Retry decision replay, sequential | `evaluate_retry` twice on separate transactions | first | second returns `Success(D₁)` with no write (row count unchanged) | `D₁` | `…::test_insert_if_absent_returns_the_stored_winner_without_writing` (the contract case re-pointed) | 4 |
| C-10 | Successor creation vs cancellation | (a) T2 `create_successor` interleaved with T1 `cancel_experiment` committing first; (b) T2 `cancel_experiment` interleaved with T1 `create_successor` committing first | T1 in both | (a) rerun finds the experiment `CANCELLED` → `CORE.INVARIANT_VIOLATION` ("a successor is created only while it is `RUNNING`"), no successor row; (b) rerun finds the experiment `RUNNING` at r+1 while the request carries r → `CONF` (`_stale`); the caller re-reads and re-issues the cancellation at the new revision (Stage 10's loop, out of scope here) | (a) experiment `CANCELLED`, no successor; (b) successor `PENDING`, experiment `RUNNING` at r+1, nothing partial | `…::test_successor_creation_and_cancellation_race_both_orders` | 6 |
| C-11 | Successor creation vs terminal aggregation | Measured first over one committed state: while slot A's latest attempt is the predecessor of an `ALLOWED` decision and no attempt bears the reserved number — the only state in which `create_successor` is eligible — `classify_experiment_outcome` row 3 (`ALLOWED_SUCCESSOR_PENDING`) makes `aggregate_experiment` return `NOT_YET_TERMINAL` and write nothing, so the two operations cannot both write against any shared start (the Stage 5 race suite recorded the same non-constructibility). (a) T2 `aggregate_experiment` interleaved with T1 `create_successor` committing after T2's first read; (b) T2 `create_successor` interleaved with a terminal write committed through the repository compare-and-swap (`RUNNING` → `FAILED`, labelled as the terminal write a winning aggregation would issue — it is not an executed `aggregate_experiment`) | (a) T1; (b) the labelled terminal write | (a) T2 returns `Success(NOT_YET_TERMINAL)` after one `begin()`, no write and no lost swap; the blocker is pinned through `build_aggregation_input` (slot A `ALLOWED_SUCCESSOR_PENDING`, slot B terminal `NO_DECISION_REQUIRED`); a fresh aggregation over the committed successor stays `NOT_YET_TERMINAL` (row 1); (b) T2's `add_attempt` is refused by the snapshot rule, the rerun's `get_by_attempt_number` probe finds no successor and the terminal experiment is `CORE.INVARIANT_VIOLATION` ("a successor is created only while it is `RUNNING`"), no write; the real `aggregate_experiment` then replays the `FAILED` verdict with `reason_codes == ()` and no clock read. What (b) proves: a successor cannot be created against a terminal experiment that landed between the creator's first read and its write. What it does not establish: an `aggregate_experiment` terminal write racing an eligible `create_successor` — that interleaving has no constructible shared start | (a) successor `PENDING` attempt 2 and the experiment bumped; (b) the terminal experiment alone, no successor; never both | `…::test_successor_creation_and_aggregation_race_both_orders` | 6 |
| C-12 | Read-set protection without a revision move | T2 `aggregate_experiment` — write-ready because slot A's latest attempt is `FAILED` with a `DENIED` decision from the real `evaluate_retry` over a non-retriable primary and slot B's is `NOT_APPLICABLE` — reads the experiment and every latest attempt; T1, in its own transaction, commits `configuration_snapshots.freeze` (`SqliteConfigurationSnapshotWriter.freeze`) on that experiment row after T2's first read: an `UPDATE experiments` of the four snapshot columns only (`configuration_snapshot_schema_version`, `configuration_snapshot_json`, `configuration_audit_hash`, `material_base_configuration_hash`), the revision column not in the `SET` list; a fresh read inside the hook proves the revision unchanged. The row is a `RUNNING` scaffolding parent inserted through `add` with no stored snapshot, the state §4.4 admits the freeze in after `QUEUED`; production freezes at `VALIDATED` before queueing. (`transition_run` on one of the read runs is unconstructible: every latest attempt the aggregation read is terminal when it reaches its write, row 1) | T1 | `CONF` at the CAS (`SQLITE_BUSY_SNAPSHOT`) although the experiment row never moved in revision; the rerun recomputes over the committed state and reaches the same `FAILED` verdict (`EXPERIMENT.SLOT_FAILED`); exactly two `begin()` calls. The companion `test_sqlite_retry_decisions.py::test_a_fresh_observation_in_the_read_set_makes_the_rerun_recompute` proves a rerun that recomputes to a different outcome (`DENIED` → `ALLOWED` once `availability_observation_writer.add` lands in `list_for_adapter`'s read set) | `FAILED` at r+1 with the frozen snapshot preserved by the record swap (§4.3.1 e); all eight consistency counts zero | `test_sqlite_driver_races.py::test_a_read_only_row_that_moved_refuses_the_aggregation_write` | 6 |
| C-13 | Spurious conflict residual (§1.4) | an unrelated commit (a diagnostic record from another connection) between T2's first read and first write, fired by `InterleavingUnitOfWork(on_attempts=(1,))`; then on both attempts with `on_attempts=(1, 2)` | — | one interleaving: rerun succeeds (`begins == 2`); two interleavings: public `CONF` with `begins == 2`, no partial write | unchanged or the operation's write | `test_sqlite_driver_races.py::test_unrelated_commits_cost_one_rerun_and_two_return_the_conflict` | 6 |
| C-14 | Event replay and conflicting content | `append_event(e)` twice; `append_event(e' same key, other content_hash)`; `append_event(e'' other key, same event_id)`; T1/T2 concurrent identical appends | first | identical → the stored event, row count unchanged; other content → `CONF`; reused `event_id` → `CONF`; concurrent loser → `CONF` returned verbatim by `Stage5InvocationLifecycle.append_event` | one row per key | `test_sqlite_run_events.py::test_append_event_replays_identical_and_refuses_conflicting_content` and `…::test_a_concurrent_identical_append_loses_as_a_conflict` | 4 |
| C-15 | Bounded busy wait | R holds `BEGIN IMMEDIATE`; T2 (`busy_timeout_ms=100`, no prior read) `experiments.add` | R | `CONF` after the busy timeout (`SQLITE_BUSY`, code 5); elapsed wall time at least the timeout and below the fixture's 2 s observation budget; no exception; T2 stays usable and rolls back | unchanged | `test_sqlite_database.py::test_a_held_writer_lock_fails_the_writer_as_a_bounded_conflict` | 1 |
| C-16 | Stale-snapshot refusal is immediate | T1 reads; R writes and commits; T1 writes | R | `CONF` with `sqlite_errorcode == 517`, elapsed below 100 ms budget | R's write | `test_sqlite_database.py::test_a_stale_snapshot_write_is_refused_immediately` | 1 |
| C-17 | Interrupted writer process | P opens the migrated database with the stdlib DBAPI, `BEGIN IMMEDIATE`, `CREATE TABLE crash_probe (x INTEGER)`, inserts one row into it (a throwaway table, so no record CHECK is involved), prints `HELD`, blocks on stdin; the parent reads `HELD`, asserts its own writer gets `CONF` (a Windows lock held by another process), then terminates P and awaits its exit; the parent reopens through `open_database` | — | none | the pre-crash committed rows are present; `schema_objects()` equals the pinned set (no `crash_probe`); `check_revision` is `CURRENT`; `quick_check` = `ok`; journal mode `wal`; `-wal`/`-shm` sidecars tolerated | `tests/integration/persistence/test_wal_restart.py::test_an_interrupted_writer_leaves_no_partial_row_after_reopen` | 6 |
| C-18 | Read-only file | the database file is set read-only (`stat.S_IREAD`) after initialization; `open_database` succeeds for reading; a write in transaction T1 | — | `PERSISTENCE.WRITE_FAILED` (`SQLITE_READONLY*`) at the write; T1 is closed by the I/O-class rule (§4.2), so every later T1 call and `commit()` return the stored `WRITE_FAILED` and `rollback()` releases it; a **fresh** transaction or read-only session on the same database then reads every row successfully | unchanged | `test_sqlite_database.py::test_a_read_only_database_file_fails_writes_with_write_failed` | 6 |
| C-19 | Missing parent directory | `open_database(<absent dir>/x.sqlite3)` | — | `PERSISTENCE.STORAGE_UNAVAILABLE`; no directory created | no file | `test_sqlite_database.py::test_open_never_creates_a_directory` | 1 |
| C-20 | Foreign or corrupt file | (a) a file with a different `application_id` and tables; (b) a non-SQLite file | — | (a) `STORAGE_UNAVAILABLE` (identity); (b) `STORAGE_UNAVAILABLE` (`SQLITE_NOTADB`); the file's SHA-256 is unchanged after the refusal | unchanged | `test_sqlite_database.py::test_a_foreign_or_corrupt_file_is_refused_without_mutation` | 1 |
| C-21 | Migration states | empty file; current; behind (constructed with a two-revision test script directory); unknown revision stamped; user tables without `alembic_version` | — | `EMPTY`/`BEHIND` refuse normal open with `MIGRATION_MISMATCH` and accept `apply_migrations`; `UNKNOWN`/`UNVERSIONED` refuse both with `MIGRATION_MISMATCH`; the file's SHA-256 unchanged after every refusal | as stated | `test_sqlite_migrations.py::test_every_revision_state_is_classified_and_refusals_do_not_mutate` | 2 |
| C-22 | Failed migration preserves the database | a test-only script directory whose second revision raises after a `create_table` | — | `apply_migrations` returns `PERSISTENCE.WRITE_FAILED` with the revision named; `check_revision` still `BEHIND` at revision one; the half-created table absent | revision one | `test_sqlite_migrations.py::test_a_failing_revision_rolls_back_to_the_prior_revision` | 2 |
| C-23 | Restart reconciliation over the real database | seed the Stage 7 `run_every_row` states (PENDING, STARTING past/before deadline, RUNNING with a scripted live/dead/reused identity, every terminal with `cleanup_complete=false` for both `process_created` values, a cancelled experiment's PENDING) across a close-and-reopen; run `reconcile_invocations` with `SqliteReconciliationSource`, the SQLite lifecycle and the scripted controller | — | every row reaches the Stage 7 plan section 8.5 decision; never `EXITED`, never a success state; a `run_facts` miss is `INV` from one snapshot | as Stage 7 plan section 8.5 | `tests/integration/persistence/test_sqlite_restart_reconciliation.py::test_every_reconciliation_row_over_a_reopened_database` | 5 |
| C-24 | Retry decision survives restart | `evaluate_retry` → `ALLOWED` with `retry_not_before_utc` in the future; close; reopen; `create_successor` (its request carrying the experiment revision after `evaluate_retry`'s bump) before the instant → `RETRY.NOT_BEFORE_NOT_REACHED`; `FixedClock.advance`; `create_successor` → `Success` with `attempt.attempt_number == reserved_successor_attempt_number` | — | — | one decision row, one successor | `test_sqlite_retry_decisions.py::test_a_durable_retry_delay_is_reused_after_reopen` | 6 |
| C-25 | Recorder before swap, orphan tolerated | (a) `record(d)` alone; (b) `record(d)`, then a `record_terminal` of the Stage 7 lifecycle over `SqliteUnitOfWork` whose CAS is refused (stale revision) | — | (a) `d` is durable and readable in a fresh session and `consistency_report().dangling_diagnostic_references == 0` (a recorded diagnostic nothing references is not dangling); (b) the terminal write never happens, `d` remains readable, the invocation is unchanged and the count stays 0 | `d` durable, invocation unchanged | (a) `test_sqlite_registries.py::test_a_recorded_diagnostic_is_durable_and_unreferenced` (Task 3, recorder and report only); (b) `test_sqlite_supervision_lifecycle.py::test_a_recorded_diagnostic_survives_a_refused_swap` (Task 5, which first has the lifecycle over SQLite) | 3, 5 |
| C-26 | Foreign-key refusals | an event for an invocation of another run; an event for a `DESCRIBE` invocation; a run with an unregistered observation; an owner naming an unpersisted run | — | `INV` at the write; nothing written | unchanged | `test_sqlite_constraints.py::test_every_composite_foreign_key_refuses_a_mismatched_reference` | 4 |
| C-27 | CHECK and trigger refusals | a raw `UPDATE` that changes a terminal state; a raw `UPDATE` of a frozen spec; a raw `UPDATE` of a frozen configuration snapshot at `QUEUED` and a raw `UPDATE` clearing one; a raw `UPDATE` of `state` to `QUEUED` on a row with no snapshot; a raw `DELETE` on every append-only table (`diagnostic_causes` included); a row violating each 15.2 state CHECK; an `experiments` row with only some of the four snapshot columns filled; a `diagnostic_causes` self-edge | — | `SQLITE_CONSTRAINT_TRIGGER`/`CHECK` → through the repository `INV`; raw statements raise `IntegrityError` | unchanged | `test_sqlite_constraints.py::test_every_trigger_and_state_check_fires` | 2 |
| C-28 | Experiment-scoped slot identity (reading 7) | (A) `experiments.add(E₁)` (spec `SLOT_A`/`SLOT_B`, the shared fixtures' shape) and `experiments.add(E₂)` (`OTHER_EXPERIMENT_ID`, built from `three_slot_draft()`: `SLOT_A`, `SLOT_B` and `SLOT_C` at ordinal 2 with the distinct pair `ADAPTER_GAMMA`/`ENGINE_GAMMA`, §7.1.1), then `add_attempt(run of E₁, SLOT_A, n=1)` **terminal** (`sample_run(_R.FAILED, observed=False)`, so the active-attempt partial index cannot be the refuser in B) and `add_attempt(run of E₂, SLOT_A, n=1)`; (B) a second `add_attempt` with E₁, `SLOT_A`, `n=1` under a new `run_id`; (C) `add_attempt(run naming E₁ with SLOT_C, adapter ADAPTER_GAMMA, engine ENGINE_GAMMA)` — a shape-valid run whose slot exists **only** under E₂ — and, as a positive control, the same run under E₂ (the run's adapter and engine equal the slot row's, so even the rolled-back control never plants a `slot_identity_mismatches` row) | — | (A) every write succeeds: two `engine_slots` rows for `SLOT_A`/`SLOT_B`, one for `SLOT_C`, two runs with the same slot and attempt number; (B) `CONF` from `UNIQUE (experiment_id, logical_slot_id, attempt_number)` alone (a schema without the triple passes the attempt because E₁'s first attempt is terminal — the assertion distinguishes the two rules); (C) `INV` (`SQLITE_CONSTRAINT_FOREIGNKEY` on `(experiment_id, logical_slot_id) → engine_slots`: the slot row exists, its experiment half differs) and the control succeeds | (A) five slot rows and two runs; (B) and (C) unchanged apart from the control's run | `test_sqlite_repositories.py::test_slot_identity_is_scoped_by_its_experiment` | 4 |
| C-29 | Multi-statement method failure after a successful earlier statement (reading 21) | a test-only trigger installed through a raw connection refuses the insert of `SLOT_B` into `engine_slots` (`BEFORE INSERT … WHEN NEW.logical_slot_id = 'slot_…B' … RAISE(ABORT)`); then (a) `experiments.add(E)` whose spec carries `SLOT_A` then `SLOT_B`; (b) `compare_and_swap` on a stored `DRAFT` experiment replacing its spec by one carrying `SLOT_A` then `SLOT_B`; (c) the same trigger shape on `dataset_partitions` for `SqliteDatasetRepository.register` with two partitions | — | each method returns `INV` (`SQLITE_CONSTRAINT_TRIGGER`), rolled back to its savepoint: in (a) `experiments.get(E)` inside the same transaction is `INV` (`does not exist`) and no `engine_slots` row of `E` exists; in (b) the stored experiment and its slot rows are unchanged; in (c) no `datasets` row exists; the transaction stays usable and a following `commit()` publishes nothing of the failed method | unchanged | `test_sqlite_repositories.py::test_a_multi_statement_method_rolls_back_to_its_savepoint` (a, b: Task 4); `test_sqlite_registries.py::test_dataset_registration_rolls_back_to_its_savepoint` (c: Task 3) | 3, 4 |
| C-30 | Compare-and-swap precedence and the zero-row branch (§4.3.1) | for each of the three repositories (`CAS_SUBJECTS`, §7.1): a swap of an unknown identity with a wrong step; a swap at `r + 5` with a replacement at `r + 1`; a swap at `r` with a replacement at `r + 2`; a swap at `r` with a replacement at `r + 1`; then, in one transaction, an insert followed by a swap, the same swap again, and a swap at the new revision; separately, a test-only `BEFORE UPDATE … RAISE(IGNORE)` trigger on the target row (`install_ignoring_update_trigger`, §7.1) under a swap that passes every check | — | `CONF` (step b), `CONF` (step c — never `INV`, although the step is also wrong), `INV` (step d, row unchanged, `get` returns the stored row), `Success` (visible to this transaction, invisible to a fresh reader until commit); the same-transaction sequence: `Success`, then `CONF` (the pre-read sees the transaction's own swap), then `Success`; the ignored `UPDATE`: `CONF` (step f, rowcount 0) with the row unchanged and the transaction usable | unchanged after every refusal; the swapped row only after commit | `test_sqlite_repositories.py::test_compare_and_swap_refuses_missing_then_stale_then_step_in_order`, `…::test_compare_and_swap_observes_this_transactions_earlier_writes`, `…::test_a_zero_row_conditional_update_is_a_conflict_after_the_checks` | 4 |
| C-31 | Causal-edge relation under the referrer-first order and under rollback (reading 23) | `record(primary citing additional)`; `record(additional)`; `record(additional)` again; then a test-only trigger refusing inserts into `diagnostic_causes` (`install_refusing_edge_trigger`, §7.1) and `record(d citing an already recorded cause)`; then a raw `DELETE` of a cited cause | — | after the first call: no edge, `unresolved_causal_references == 1`, `causal_edge_mismatches == 0`; after the second: the edge `(primary, additional)` present, both counts 0; the third call writes nothing (row count of `diagnostic_causes` unchanged); the refused call returns `INV` and **neither** the diagnostic row nor an edge is committed (the recorder's one transaction rolled back); the raw `DELETE` raises `IntegrityError` (T-APPEND-ONLY on `diagnostics`; the `RESTRICT` clause is pinned by `EXPECTED_SCHEMA_OBJECTS`) | as stated | `test_sqlite_registries.py::test_causal_edges_converge_under_the_referrer_first_order`, `…::test_a_refused_edge_rolls_the_diagnostic_back_with_it`, `…::test_a_cited_cause_cannot_be_deleted` | 3 |
| C-32 | Frozen configuration snapshot at the queue edge (reading 22) | `VALIDATED` experiment whose spec was built from `config_backed_spec(ApplicationConfig())` (§7.1); `compare_and_swap` to `QUEUED` before any freeze; `configuration_snapshots.freeze(snapshot_configuration(other_config()))` then the swap; `freeze(snapshot_configuration(ApplicationConfig()))` (a pre-`QUEUED` replacement) then the swap; after commit `freeze` of a different snapshot; `get`; a raw `UPDATE` of one snapshot byte | — | `INV` (step d′: no snapshot); `INV` (step d′: the snapshot's base hash and derived retry policy disagree with the spec); `Success`; `INV` (frozen at `QUEUED`; the identical snapshot is an idempotent `Success`); `get` equals the frozen `ConfigSnapshot`; the raw `UPDATE` raises `IntegrityError` (T-EXP-SNAPSHOT-FROZEN) and, on a `DRAFT` row without the trigger's guard, a tampered byte makes `get` return `INV` | `QUEUED` at r+1 with the default snapshot frozen; nothing else | `test_sqlite_repositories.py::test_queueing_requires_a_frozen_snapshot_that_agrees_with_the_spec`, `test_sqlite_registries.py::test_a_frozen_snapshot_round_trips_and_a_tampered_byte_is_refused` | 3, 4 |

### 5.2 Deterministic synchronization rules

- Two `SqliteTransaction`s on separate connections are interleaved from one
  test thread in call order; the outcomes of C-1–C-4, C-9, C-14, C-16, C-26 and
  C-30–C-32 need no thread.
- A held writer lock (C-15, C-17) is a raw `sqlite3` connection holding
  `BEGIN IMMEDIATE`, or a child process that prints `HELD` after acquiring it;
  the parent proceeds only after reading that line (never after a sleep).
- Interleavings inside a driver run (C-5–C-8, C-10–C-13) use
  `persistence_support.harness.InterleavingUnitOfWork(inner, *, after_read=<callable>, on_attempts=(1,))`
  (Task 6), which wraps a `SqliteUnitOfWork`, counts `begin()` calls in
  `begins`, and runs the callable once per listed attempt, after that attempt's
  first repository read (the same shape as the doubles'
  `MemberOverridingUnitOfWork` and one-shot hooks). The callable commits the
  winner on its own connection. `on_attempts=(1, 2)` builds the two-interleaving
  half of C-13.
- Clocks are `FixedClock`s; observation expiry (C-7) is a clock advance, never a
  wall-clock wait.
- The child process (C-17) is launched with a list argv, `shell=False`, the
  venv interpreter, `-I -B -c` and a single-line program (the launcher and the
  Stage 6 shell scan forbid anything else); it is terminated by the test's
  `finally:` and its exit is awaited before the reopen.

### 5.3 Bounded operation deadlines versus fixture observation budgets

| Quantity | Kind | Value | Where asserted |
|---|---|---|---|
| `busy_timeout_ms` | operation deadline (configuration, `100..60000`, default `5000`) | tests use `100` through `DatabaseConfig(busy_timeout_ms=100)`; production keeps the configured value | read back as `PRAGMA busy_timeout` on every connection (§6.1) |
| stale-snapshot refusal | operation behaviour | immediate | C-16 asserts elapsed below a 100 ms budget |
| lock-wait observation budget | fixture | 2 s (twenty times the configured timeout) | C-15, C-17 assert elapsed below the budget and above the configured timeout minus scheduler jitter (the lower bound proves the wait happened) |
| child readiness | fixture | the `HELD` line | C-17 |
| pool checkout | operation deadline | proposed 5 s pool timeout, then `STORAGE_UNAVAILABLE` | Task 1 probe with a pool of one and a second checkout |

No test asserts an absolute duration of a database operation; the only timing
assertions are the two bounds above, both derived from the configured timeout.

---

## 6. SQLite and migration contract (matrix D)

### 6.1 Connection policy

Applied by `SqliteDatabase` on every physical connection, before the connection
is handed to any transaction, and read back; a mismatch closes the connection
and fails the caller with `PERSISTENCE.STORAGE_UNAVAILABLE`.

| Setting | Value | Scope | Applied | Verified by |
|---|---|---|---|---|
| `journal_mode` | `wal` | persistent in the file | `PRAGMA journal_mode=WAL` on the first connection of `open_database`/`open_for_migration` (outside any transaction) | read back `= 'wal'` on every physical connect; Task 1 probe reopens the file and reads `wal` |
| `foreign_keys` | `ON` (`1`) | per connection | connect hook | read back `= 1`; Task 4's foreign-key cases prove enforcement |
| `synchronous` | `FULL` (`2`) | per connection | connect hook | read back `= 2` |
| `busy_timeout` | `DatabaseConfig.busy_timeout_ms` (default `5000`, range `100..60000`) | per connection | connect hook `PRAGMA busy_timeout=<ms>` (the DBAPI `timeout` argument is set to the same value) | read back `= <ms>`; C-15 |
| DBAPI transaction control | disabled (`isolation_level = None`); `BEGIN` issued explicitly by the unit of work | per connection | connect hook | Task 1 probe (§2.8) |
| `application_id` | `0x434C4231` (`CLB1`, a fixed constant `APPLICATION_ID`) | persistent in the file | set by `open_for_migration` when the state is `EMPTY`, before the baseline revision runs | read back on every open; a different non-zero value is `STORAGE_UNAVAILABLE` |
| `query_only` | not used | — | — | the read-only session is structural (§4.5) |
| DBAPI thread check | disabled (`check_same_thread=False`) | per connection | connect arguments | Task 1 probe: a pooled connection re-used from another thread |
| pool | bounded queue pool, size 8, overflow 2, checkout timeout 5 s (proposed; names confirmed by the probe) | engine | `SqliteDatabase.open` | exhaustion → `STORAGE_UNAVAILABLE`, never a hang |

Nothing else is configured: no `mmap_size`, `cache_size`, `temp_store`,
`locking_mode` or `journal_size_limit` change; `wal_autocheckpoint` keeps its
default. Checkpointing is SQLite's; `SqliteDatabase.close()` disposes the pool
(closing every connection, which lets SQLite checkpoint and remove the sidecars
when no other process holds the file) and is called by every test fixture and
by Stage 10's composition root on shutdown.

### 6.2 Opening a database

```text
database_path(runtime_root: Path, config: DatabaseConfig) -> Path
    pure: runtime_root / config.filename; runtime_root must be absolute (ValueError otherwise)

open_database(path: Path, *, busy_timeout_ms: int, clock: Clock) -> Result[SqliteDatabase]
    1. path is absolute, its parent exists and is a directory, path is not a directory
       (else STORAGE_UNAVAILABLE; nothing is created)
    2. build the engine (pool, connect hook); take one connection
    3. read application_id: 0 with no user tables -> EMPTY candidate; APPLICATION_ID -> ours;
       anything else -> STORAGE_UNAVAILABLE
    4. PRAGMA journal_mode=WAL (idempotent), read back every §6.1 setting
    5. PRAGMA quick_check -> exactly one row 'ok' (else STORAGE_UNAVAILABLE)
    6. check_revision -> must be CURRENT (else MIGRATION_MISMATCH carrying state, current, head)
    7. return the database; the connection returns to the pool

open_for_migration(path, *, busy_timeout_ms, clock) -> Result[SqliteDatabase]
    steps 1-5, then check_revision in {EMPTY, BEHIND, CURRENT} (else MIGRATION_MISMATCH);
    when EMPTY: set application_id = APPLICATION_ID; return the database for apply_migrations
```

Every refusal is a read-only outcome: Task 1 and Task 2 hash the file before
and after each refused open and assert equality (C-20, C-21). The file is
created by SQLite on the first successful `open_for_migration` of an absent path
(the only creation Stage 8 performs); a normal `open_database` on an absent path
is `STORAGE_UNAVAILABLE`, not a creation.

### 6.3 Transaction boundaries and lock contention

The unit of work (§4.2) is the only writer boundary: one deferred transaction
per `begin()`, the writer lock taken at the first write, released at
`commit()`/`rollback()` (`rollback()` checks the DBAPI's `in_transaction`
first, because an I/O error may already have ended the SQLite transaction).
Read-only sessions (§4.5) never take it. Lock
contention is bounded by `busy_timeout` and always ends in a `Failure`, never
an exception or a hang (C-15); a stale snapshot is refused immediately (C-16).
No write transaction is held across process execution, heartbeat waiting,
hashing or unrelated file I/O: the operations that use the unit of work perform
in-memory work only (§4.1), the lifecycle records diagnostics between
transactions, and Task 7's composition test asserts through a counting unit of
work that zero transactions are open while `WindowsProcessSupervisor.invoke`
awaits the child. The recorder's autonomous transaction (§4.4) holds the lock
for one insert.

### 6.4 Revision states and the migration runner

`migration_runner.py` (the only importer of `alembic.command`, `alembic.config`,
`alembic.script`, `alembic.runtime`):

| Function | Behaviour |
|---|---|
| `expected_head(*, script_location: Path \| None = None) -> str` | `ScriptDirectory.from_config(_config(script_location)).get_heads()`; exactly one head or `RuntimeError` (a second head is a programmer defect the single-head test catches). `script_location` defaults to the packaged directory; the keyword exists only so Task 2's tests can point at a temporary two-revision script directory (C-21 `BEHIND`, C-22) |
| `check_revision(connection, *, script_location: Path \| None = None) -> RevisionReport` | `RevisionReport(state, current_revision: str \| MISSING, expected_head: str)` with `state` in `RevisionState = {EMPTY, CURRENT, BEHIND, UNKNOWN, UNVERSIONED}`: no `alembic_version` and no user tables → `EMPTY`; `alembic_version` holding the head → `CURRENT`; holding another revision known to the script directory → `BEHIND`; holding an unknown identifier → `UNKNOWN` (an unsupported newer or foreign database, spec 23.4); user tables but no `alembic_version` → `UNVERSIONED` |
| `apply_migrations(database, *, script_location: Path \| None = None) -> Result[RevisionReport]` | requires `EMPTY` or `BEHIND` (else `MIGRATION_MISMATCH`); runs `alembic.command.upgrade(config, "head")` with the database's connection placed in `config.attributes["connection"]`, each revision inside one SQLite transaction (transactional DDL); a raising revision rolls back to the prior revision and returns `WRITE_FAILED` naming the revision (C-22); returns the `CURRENT` report |
| `metadata_drift(connection) -> tuple[str, ...]` | `alembic.autogenerate.compare_metadata` between the live database and `schema.metadata`, rendered as stable one-line descriptions; empty on a migrated database (Task 2 test and `verify_migrations.py`); the comparison's SQLite blind spots (CHECK expressions, trigger DDL, partial-index `WHERE`) are covered by `schema_objects(connection)` |
| `schema_objects(connection) -> tuple[SchemaObject, ...]` | rows of `sqlite_master` (type, name, table, normalized SQL) for every table, index and trigger; Task 2 pins the exact set and SQL text of §3.3–§3.4 |
| `_config() -> Config` | programmatic `alembic.config.Config()` with `script_location` set to the packaged `migrations` directory (resolved from the module's own `__file__`, never from cwd) and `version_path_separator` fixed; no `alembic.ini`, no logging configuration |

`env.py` (reading 16): defines `run_migrations(connection)` that configures the
`EnvironmentContext` with `target_metadata=schema.metadata`,
`render_as_batch=True`, `transaction_per_migration=True` and runs the
migrations; at module level it runs only when the Alembic proxy is established.
It imports `sqlalchemy` (for typing), `alembic.context` (aliased) and
`crypto_lab.persistence.schema`; nothing else.

`versions/r0001_stage8_baseline.py`: `revision = "r0001_stage8_baseline"`,
`down_revision = None`; `upgrade()` creates the thirteen tables of §3.3 in
dependency order (`experiments`, `engine_slots`, `runtime_availability_observations`,
`diagnostics`, `diagnostic_causes`, `strategy_versions`, `datasets`, `dataset_partitions`,
`engine_runs`, `command_invocations`, `run_events`, `retry_decisions`,
`artifact_owners`) with every CHECK, UNIQUE and foreign key inline, then every
index (partial indexes and triggers through `op.execute(text(...))` with the SQL
constants exported by `schema.py` so the metadata module and the revision share
one definition); `downgrade()` drops triggers, indexes and tables in reverse
order. The Alembic version table is `alembic_version` with its default shape.

Stage 9 and later add `r0002_<stage>_<topic>` revisions; a database at
`r0001_stage8_baseline` then classifies as `BEHIND`, the first constructible
"behind" case in production (Task 2 constructs it with a test-only script
directory of two revisions).

### 6.5 Stable failure mapping (single authority)

`SqliteDatabase.classify(error) -> ErrorCode` reads `sqlite_errorcode` from the
wrapped DBAPI exception (`error.orig`) and maps:

| SQLite result (extended) | Code | Diagnostic |
|---|---|---|
| `SQLITE_BUSY` (5) and every `SQLITE_BUSY_*` incl. `SQLITE_BUSY_SNAPSHOT` (517); `SQLITE_LOCKED` (6) | busy / stale snapshot | `PERSISTENCE.CONCURRENCY_CONFLICT` |
| `SQLITE_CONSTRAINT_UNIQUE` (2067), `SQLITE_CONSTRAINT_PRIMARYKEY` (1555) | duplicate identity or index collision | `PERSISTENCE.CONCURRENCY_CONFLICT` |
| a compare-and-swap pre-read finding no row or a stored revision other than the expected one (§4.3.1 steps b–c); rowcount 0 on the conditional `UPDATE` (step f) | missing, moved or stale row | `PERSISTENCE.CONCURRENCY_CONFLICT` |
| `SQLITE_CONSTRAINT_FOREIGNKEY` (787), `SQLITE_CONSTRAINT_CHECK` (275), `SQLITE_CONSTRAINT_TRIGGER` (1811), `SQLITE_CONSTRAINT_NOTNULL` (1299) | impossible aggregate state | `CORE.INVARIANT_VIOLATION` |
| `SQLITE_FULL` (13), every `SQLITE_IOERR_*` (10 + n·256), every `SQLITE_READONLY_*` (8 + n·256), `SQLITE_CANTOPEN` during a write | write failed | `PERSISTENCE.WRITE_FAILED` |
| `SQLITE_CORRUPT` (11), `SQLITE_NOTADB` (26), `SQLITE_CANTOPEN` (14) at open, `SQLITE_PERM` (3), `SQLITE_AUTH` (23), a PRAGMA read-back mismatch, `quick_check` ≠ `ok`, a foreign `application_id`, pool exhaustion (the pool's own checkout-timeout error, which is not a DBAPI error and is caught by its own branch in `begin()`) | storage unavailable | `PERSISTENCE.STORAGE_UNAVAILABLE` |
| revision state not admitted by the entry point | migration mismatch | `PERSISTENCE.MIGRATION_MISMATCH` |
| egress `ValidationError`, `get`/`get_many` miss, revision-step violation (§4.3.1 step d, after the pre-read matched), frozen-spec guard, queue-edge snapshot guard (step d′), a frozen snapshot re-frozen, N4 present value | invariant | `CORE.INVARIANT_VIOLATION` |
| any other DBAPI error | unclassified storage fault | `PERSISTENCE.STORAGE_UNAVAILABLE` with the numeric code in `details` |

`details` always carries `{"sqlite_errorcode": <int>, "sqlite_errorname": <str>,
"table": <str>, "operation": <str>}` where known and never the SQL text of a
statement that could contain row values. Every mapped `Failure` is one
diagnostic, category `PERSISTENCE` (or `INTERNAL_INVARIANT`), `source_component`
`persistence`, `retriable` per §2.5 reading 9, stamped from the injected clock.

### 6.6 Migration consistency script and launcher profile

`scripts/verify_migrations.py` (no `subprocess`, no network; strict mypy and
ruff like `generate_schemas.py`): creates a temporary directory, runs
`open_for_migration` + `apply_migrations` on `<tmp>/verify.sqlite3`, asserts
exactly one head, `check_revision` → `CURRENT`, `metadata_drift` empty,
`schema_objects` equal to the pinned expectation exported by `schema.py`,
every §6.1 setting read back, `quick_check` `ok`, `PRAGMA foreign_key_check`
empty; then closes and removes the temporary directory. Exit `0` on success,
`1` with a one-line reason per failed check. It reads no configuration and no
environment.

Launcher profile `migration-check` (Task 2), a clause in the Python-bearing
switch following the `schema-generate-check` shape:
`$runPrefix + @($pythonExecutable, "-I", "-B", <Resolve-ClosedRepositoryPath scripts\verify_migrations.py>)`,
no arguments accepted. `scripts/verify.ps1` gains
`==> Check migrations` invoking the profile between "Check generated schemas" and
"Run test suite" (roadmap gate 8 from Stage 8 onward). Every pin the change
trips is listed in §2.6 (Launcher and verifier pins).

### 6.7 Packaging and distribution

The migration tree lives under `src/crypto_lab/persistence/migrations/`, so the
pinned hatch configuration (`packages = ["src/crypto_lab"]`) packages
`env.py`, `script.py.mako` and every `versions/*.py` with the wheel and the sdist
(`/src`); the wheel at the planning base already contains every non-ignored file
under the package. `scripts/verify_schema_distribution.py` filters to the schema
prefix and is unaffected. Task 8 records the wheel's `persistence/migrations`
listing in the ledger after the final `build` as a reviewed fact. No
`alembic.ini`, no root-level migration directory, no `force-include` change.

---

## 7. Test strategy, harness and the contract-suite disposition

### 7.1 The SQLite test support package (`tests/persistence_support/`; created in Task 1, extended in Tasks 2, 3, 4, 6 and 7)

| Helper | Shape | Used by |
|---|---|---|
| `open_test_database(tmp_path: Path, *, busy_timeout_ms: int = 100, clock: Clock) -> SqliteDatabase` (Task 2) | `open_for_migration` on `tmp_path / "registry.sqlite3"`, then `apply_migrations` only when the report is `EMPTY` or `BEHIND` (a `CURRENT` file reopens unchanged, so one helper serves the first open and every reopen); returns the database; the caller closes it in `finally:` or through the `sqlite_database` fixture | every SQLite test |
| `SqliteHarness(database: SqliteDatabase)` (implements `PortHarness`; `database` is a public attribute) | `unit_of_work()` → a fresh `SqliteUnitOfWork(database, FixedClock(INSTANT))` whose open transactions the harness tracks; `seed_diagnostic(d)` → `SqliteDiagnosticRecorder.record` (autonomous); `seed_observation(o)` → the writer in its own transaction; `committed_experiments/engine_runs/command_invocations/retry_decisions()` → a read-only session, decoded, sorted by identity; `close()` → rolls back every transaction still open (an abandoned `del`-ed transaction included), then `database.close()` — the fixture calls it in teardown so no lock or handle survives a test | the `harness` fixture's `"sqlite"` parameter |
| `put_lifecycle_parents(harness, *, experiment_id: str = EXPERIMENT_ID, run: bool = False, invocation: bool = False, observation: bool = False)` | inserts, each in its own committed transaction and only when absent, the parents the shared fixtures reference: `sample_experiment(_E.QUEUED, experiment_id=experiment_id)` (its spec carries exactly `SLOT_A` and `SLOT_B`, projected into `engine_slots` under that experiment — reading 7 makes two experiments with the same slot identifiers legal), then `sample_observation(AVAIL_A)` when `observation`, then `sample_run(_R.PENDING, experiment_id=experiment_id)` (`RUN_ID`, slot `SLOT_A`) when `run`, then `sample_invocation(_C.RUNNING)` (`INVOCATION_ID`, run `RUN_ID`) when `invocation`; `invocation=True` implies `run=True` (the invocation's foreign key needs the run) and the helper asserts it; harmless for the in-memory kind. The helper freezes **no** configuration snapshot: the seeded parent is inserted directly at `QUEUED` through `add` (scaffolding that never crosses the queue edge of §4.3.1 step d′), so `consistency_report().queued_without_snapshot` counts it (§4.6) and only Task 7's flows, which queue through `queue_experiment`, assert that count | the contract suite (§7.2), the event and race tests |
| public helpers `ok`, `code` (Task 1) and `commit`, `put_experiment`, `put_run`, `put_invocation`, `bump`, `bump_run`, `bump_invocation` (Task 4) | the same shapes as the shared contract module's private `_ok`, `_code`, `_commit`, `_put_*`, `_bump*` helpers, defined in `harness.py` so the new modules can import them (the contract module's names stay private and are not imported): `ok`/`code` are the two `Result` narrowers every task's tests use from Task 1 onward; the rest need the repositories and arrive with Task 4; the RED sketches below write the private names as shorthand for these | every SQLite test |
| `InterleavingUnitOfWork(inner: SqliteUnitOfWork, *, after_read: Callable[[], None], on_attempts: tuple[int, ...] = (1,))` (Task 6) | wraps the root; `begin()` counts into `begins`; for each listed attempt number the first repository read of that transaction runs `after_read` once after returning its value | §5.1 C-5–C-8, C-10–C-13 |
| `CountingUnitOfWork(inner)` (Task 6) | wraps a `SqliteUnitOfWork`; `begin()` returns the inner transaction wrapped so that `commit()`/`rollback()` decrement; exposes `open_now: int` and `max_open: int` and `reset_max()`; it has no notion of a child — Task 7's `SupervisedSqliteFlow` samples `open_now` from its `RecordingObserver` hooks (§7.1.2) and exposes the maximum as `max_open_during_child`, the one name the sketches assert | Task 7's "no transaction across the child" assertion |
| `raw_connection(path)` (Task 1) | a `sqlite3.connect` with `isolation_level=None` for lock holders and raw statements | C-15, C-16, C-27 |
| `file_sha256(path)` (Task 1) | for the no-mutation assertions | C-20, C-21 |
| `accept_any_revision(connection) -> Result[None]` (Task 1) | the accepting `revision_policy` the Task 1 database probes pass to `SqliteDatabase.open` (written `_accept` in the sketches); it returns `Success(None)` without reading the connection, so an unmigrated file opens | Task 1, `bare_database` |
| `sql_identity_literal(identity: str) -> str` (Task 4) | asserts the value matches the fixture identifier grammar `^[a-z]+_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$` (the doubles' prefixed UUID4 constants) and returns it single-quoted. SQLite admits no bound parameter inside `CREATE TRIGGER` (`trigger cannot use variables`), so the three test trigger installers compose their DDL from fixed text plus this checked literal of a fixture constant — never from a row value and never as a general interpolation — while every data statement of the tests keeps bound parameters; trigger construction and parameterized data operations stay separate | the trigger installers |
| `install_refusing_partition_trigger(database: SqliteDatabase, ordinal: int)` (Task 3) | through `raw_connection(database.path)`: `CREATE TRIGGER test_refuse_partition BEFORE INSERT ON dataset_partitions WHEN NEW.ordinal = <str(int(ordinal))> BEGIN SELECT RAISE(ABORT, 'test: partition refused'); END` (fixed text plus an integer literal; no identity, no parameter) | C-29 (c) |
| `install_refusing_edge_trigger(database: SqliteDatabase)` (Task 3) | `CREATE TRIGGER test_refuse_edge BEFORE INSERT ON diagnostic_causes BEGIN SELECT RAISE(ABORT, 'test: edge refused'); END` (fixed text, no identity) | C-31 |
| `install_refusing_slot_trigger(database: SqliteDatabase, logical_slot_id: str)` (Task 4) | through `raw_connection(database.path)`: `CREATE TRIGGER test_refuse_slot BEFORE INSERT ON engine_slots WHEN NEW.logical_slot_id = <sql_identity_literal(logical_slot_id)> BEGIN SELECT RAISE(ABORT, 'test: slot refused'); END` | C-29 (a), (b) |
| `install_ignoring_update_trigger(database: SqliteDatabase, table: str, identity_column: str, identity: str)` (Task 4) | `CREATE TRIGGER test_ignore_update BEFORE UPDATE ON <table> WHEN NEW.<identity_column> = <sql_identity_literal(identity)> BEGIN SELECT RAISE(IGNORE); END`, where `(table, identity_column)` must be one of the fixed pairs `("experiments", "experiment_id")`, `("engine_runs", "run_id")`, `("command_invocations", "invocation_id")` — SQLite's `RAISE(IGNORE)` skips the row silently, so a conditional `UPDATE` whose checks all passed reports zero affected rows: the only constructible way to reach §4.3.1 step f by rowcount inside one connection | C-30 |
| `causal_edges(database: SqliteDatabase) -> tuple[tuple[str, str], ...]` (Task 3) | raw `SELECT diagnostic_id, causal_diagnostic_id FROM diagnostic_causes ORDER BY 1, 2` through `raw_connection(database.path)` | C-31, Task 7 |
| `sample_strategy_version() -> StrategyVersion` (Task 3) | one valid `StrategyVersion` over a fixed `StrategySpec` and `StrategySourceProvenance` at `INSTANT`, the same shape `tests/unit/strategy/test_strategy_versioning.py::_version` builds, with `content_hash` computed by the versioning module's own hash function so the record's `validate_identity_is_recomputed` accepts it; a second call returns an equal record | Task 3 registry tests, Task 7 (`register` and `get_by_hash`) |
| `sample_dataset_with_partitions() -> tuple[DatasetDescriptor, tuple[DatasetPartition, ...]]` (Task 3) | one `DatasetDescriptor` and exactly two `DatasetPartition`s at ordinals 0 and 1 (the shape `tests/unit/datasets/test_dataset_metadata_hashing.py::_partition` builds), identity-consistent through `validate_dataset_identity(descriptor, partitions)`; the second partition is the one C-29 (c)'s trigger refuses | Task 3 registry tests, C-29 (c), Task 7 |
| `SupervisedSqliteFlow` (Task 7, `tests/persistence_support/supervised.py`) | the test-support composition of §7.1.2: the eight selected Stage 6 rows through the production supervisor over the planned SQLite persistence; members `open(tmp_path, *, config)`, `scenario(name)`, `describe(row)`, `prepare_run(row)`, `invoke(row, run)`, `conclude(row, run, outcome)`, `fresh_invocation(invocation_id)`, `fresh_run(run_id)`, `fresh_events(invocation_id)`, `fresh_diagnostic(diagnostic_id)`, `fresh_observation(observation_id)` (each opens a new `SqliteUnitOfWork` after the writer's last operation returned), `run_states()`, `consistency_report()`, `reconcile()` (S-8: `reconcile_invocations` over `SqliteReconciliationSource`), `independent_counts(invocation_id)` and `token_absent_everywhere(run_id)` (both over `raw_connection`, a stdlib `sqlite3` connection independent of the engine), `database_sha256()` (`file_sha256` of the closed-checkpoint file), `max_open_during_child`, `close()`, and the class method `reopen(tmp_path)`; `prepare_run(row)` returns the `READY` `EngineRunRecord` whose `run_id` the tests cite | Task 7 |
| the pure fixture constructors of `tests/persistence_support/fixtures.py` (Task 4): `ADAPTER_GAMMA`, `ENGINE_GAMMA`, `THIRD_SLOT`, `three_slot_draft`, `three_slot_experiment`, `other_spec`, `other_slots_spec`, `config_backed_draft`, `config_backed_spec`, `supervised_draft`, `other_config`, `retrying_config` | exactly the module of §7.1.1 (one authoritative definition; the task creates the file from that fence verbatim); they import `crypto_lab.configuration`, `crypto_lab.domain`, the doubles and the two fake-catalog identities of `contract.harness` only — no persistence module, no database, no clock | C-28, C-29 (b), C-32, Task 4, Task 7 |
| `CasSubject` (frozen dataclass) and `CAS_SUBJECTS: tuple[CasSubject, ...]` (Task 4) | one subject per compare-and-swap repository: `name`, `member` (`"experiments"`, `"engine_runs"`, `"command_invocations"`), `seed_parents(harness)` (nothing; `put_lifecycle_parents(harness)`; `put_lifecycle_parents(harness, run=True)`), `record()` (`sample_experiment(_E.DRAFT)`, `sample_run(_R.PENDING)`, `sample_invocation(_C.PENDING)`), `put(harness, record)` (the promoted `put_*`), `identity(record)`, `rekey(record)` (the same shape under the unknown identity `…_{UUID_E}`), `bump(record)` (`bump`, `bump_run(·, VALIDATING)`, `bump_invocation(·, STARTING)`), `insert(repository, record)` (`add`, `add_attempt`, `add`), `committed(harness)` (the matching `committed_*`) | C-30 |
| pytest fixtures of `tests/unit/persistence/conftest.py` (`tests/integration/persistence/conftest.py` is Task 5's) | **Task 1** creates the module with `fixed_clock` (`FixedClock(INSTANT)`) and `bare_database`: an **unmigrated** `SqliteDatabase.open(tmp_path / "bare.sqlite3", busy_timeout_ms=100, clock=fixed_clock, revision_policy=accept_any_revision)`, closed in teardown, for the Task 1 probes that create throwaway tables (C-15, C-16). **Task 2** adds the **migrated** `sqlite_database` (`open_test_database(tmp_path, clock=fixed_clock)`, closed in teardown), `seeded_database` (`sqlite_database` plus the raw `INSERT` rows of `test_sqlite_constraints.py::SEED_STATEMENTS` — one shape-valid literal row per table in the §6.4 dependency order, executed through `raw_connection`, because no codec exists before Task 3) and `two_revision_script_directory` (a `tmp_path` copy of the packaged script directory plus a generated `r0002_test_failing.py` whose `upgrade()` calls `op.create_table("half_table", …)` and then raises `RuntimeError`; C-21 `BEHIND`, C-22). **Task 4** adds `sqlite_harness` (`SqliteHarness(sqlite_database)`, closed in teardown). The two database fixtures are distinct on purpose — the Task 1 probes need a file with no schema, every later test needs the migrated one — and no fixture is redefined by a later task | — |

Ownership by task (the file lists of §8 repeat it, and no task uses a helper
or fixture before the task that creates it): **Task 1** creates
`tests/persistence_support/__init__.py` and `tests/persistence_support/harness.py`
with `raw_connection`, `file_sha256`, `accept_any_revision`, `ok` and `code`,
and `tests/unit/persistence/conftest.py` with `fixed_clock` and `bare_database`;
**Task 2** adds `open_test_database` to `harness.py` and the three migrated
fixtures to the conftest; **Task 3** adds `causal_edges`,
`install_refusing_edge_trigger`, `install_refusing_partition_trigger`,
`sample_strategy_version` and `sample_dataset_with_partitions` to `harness.py`
(they need only `raw_connection`, the Task 2 schema and the committed record
modules) and `SqliteDatabase.consistency_report()` to `database.py` (§4.6; its
eight counts are read-only SQL over the Task 2 schema, so the whole report is
implemented there and no count is a placeholder); **Task 4** adds
`SqliteHarness`, `put_lifecycle_parents`, the remaining promoted helpers,
`sql_identity_literal`, `install_refusing_slot_trigger`,
`install_ignoring_update_trigger` and `CasSubject`/`CAS_SUBJECTS` to
`harness.py`, creates `tests/persistence_support/fixtures.py` from the fence of
§7.1.1 and adds `sqlite_harness` to the conftest; **Task 6** adds
`InterleavingUnitOfWork` and `CountingUnitOfWork`; **Task 7** adds
`DurableFlow` to `harness.py` and creates `tests/persistence_support/supervised.py`
holding `SupervisedSqliteFlow` (§7.1.2). Names a sketch uses that no row above
defines — `_pragma` (Task 1), `stamp_unknown_revision` (Task 2), `slot_rows`
and `expected_slot_rows` (Task 4), `total_changes` (Task 5), `RECONCILIATION_SEED`,
`EXPECTED_TARGET_ORDER`, `RESTART_ROWS`, `RestartRow`, `LifecycleFixture`,
`sqlite_lifecycle_over` (Task 5), `RetryFixture` (Task 6) — are module-local
helpers of the test module that names them, created in that task and never
promoted; `_ok`/`_code`/`_commit`/`_put_*`/`_bump*`/`_accept` are the promoted
helpers' shorthand. The dependency walk of §8 (Task 8's independent review
repeats it) checks, for every helper and fixture named in a sketch, that the
task creating it is the same or an earlier task and that its own imports exist
at that boundary: Task 3's tests use only Tasks 1–3 interfaces
(`sqlite_database`, `fixed_clock`, `raw_connection`, `ok`/`code`, the codecs,
the registries, the five Task 3 helpers and `consistency_report()`), never
`fixtures.py`, the lifecycle repositories or `SqliteHarness`.

The package imports `crypto_lab.persistence` (from Task 1 onward),
`crypto_lab.configuration` (`ApplicationConfig`, `RetryConfig`,
`SchedulerConfig`, `snapshot_configuration`, `material_base_configuration_hash`,
`retry_policy_from_config`), `crypto_lab.domain` (`build_experiment_spec`,
`experiment_spec_hash`, `SelectedEngineSlot`, `AdapterIdentity`,
`EngineIdentity`, `ComparisonLevel`, `RetryTerminalState`), the doubles'
builders (`from doubles.experiments import …`, the shared test convention),
`contract.harness` (only `FAKE_ADAPTER_VERSION` and `FAKE_ENGINE`, imported by
`fixtures.py` for `supervised_draft`; `contract` sorts before `crypto_lab`
under the repository's isort configuration), the stdlib `sqlite3`, and — in
`supervised.py` only — the Stage 6/7 packages and production modules §7.1.2
enumerates (`contract.scenarios`, `doubles.supervision`,
`crypto_lab.adapters.*`, `crypto_lab.process_supervision.*`); it never imports
`subprocess` (the one child-process test imports it directly and is the
twelfth allowlisted importer; `WindowsProcessController` launches the fake
children inside `crypto_lab.process_supervision`, which is not a test module)
and never mentions `os.system`.

#### 7.1.1 The pure fixture constructors (single authority)

`tests/persistence_support/fixtures.py` is exactly the module below; Task 4
creates it from this fence verbatim and every sketch that names one of its
members refers to this definition. The module constructs canonical models only
— it opens no database, reads no clock and imports no `crypto_lab.persistence`
module — so its correctness is decided by the committed validators alone:

- **The third slot** (`THIRD_SLOT`, used by `three_slot_draft`,
  `three_slot_experiment` and `other_slots_spec`; C-28, the slot-projection
  test) carries `SLOT_C` (`slot_{UUID_C}`, the doubles' constant) at ordinal 2
  with `ADAPTER_GAMMA` = `("adapter.gamma", "3.0.0")` and `ENGINE_GAMMA` =
  `("engine.gamma", "1.0.0")`. The committed collection rule
  `_validate_selected_engine_slots` requires every
  `(adapter_name, adapter_version, engine_name, engine_version)` tuple of a
  spec to be distinct ("each adapter and engine pair may be selected only
  once"), on `ExperimentSpecDraft` and `ExperimentSpec` alike; under that key
  the three pairs `("adapter.alpha", "1.0.0", "engine.alpha", "2.3.4")`,
  `("adapter.beta", "1.2.0", "engine.beta", "2.3.4")` and
  `("adapter.gamma", "3.0.0", "engine.gamma", "1.0.0")` are pairwise distinct.
  The gamma identities are the deterministic synthetic pair the Stage 5
  in-memory flow already uses for its third slot
  (`tests/integration/experiments/test_stage5_in_memory_flow.py`, module
  constants); they name no real engine and touch no production catalogue.
  A third slot that reuses an existing pair (the round-4 defect) is refused by
  the validator at construction, before any repository is reached.
- **`three_slot_experiment`** passes `sample_slot_compatibility(draft)` for
  the three-slot draft (the compatibility tuple must name every slot; the
  third resolves to `avail_{UUID_C}`) and is meant for `QUEUED` and later
  states, where `sample_experiment` includes compatibility; a `DRAFT`/`VALIDATED`
  record must not carry it.
- **`other_spec`** changes one non-slot field through the canonical builder —
  `comparison_level` `LEVEL_2` → `LEVEL_1` (`ComparisonLevel` has three
  members) — so `configuration_hash` is recomputed from `MATERIAL_HASH` and a
  `QUEUED` record's `slot_compatibility` for `SLOT_A`/`SLOT_B` still aligns.
  **`other_slots_spec`** changes the slot set instead and is used only on
  `DRAFT` records.
- **`config_backed_draft`/`config_backed_spec`** carry
  `retry_policy_from_config(config.scheduler.retry)` and, for the spec,
  `material_base_configuration_hash(config)`, so the two equalities of §4.3.1
  step d′ hold against `snapshot_configuration(config)`; the `sample_*`
  records never satisfy them (their base hash is the fixture constant
  `MATERIAL_HASH`, which no `ApplicationConfig` yields).
- **`retrying_config`** is the smallest explicit configuration under which the
  Task 7 durable flow can reach its asserted successor: two attempts per slot
  (slot A's initial attempt and its one successor; slot B, whose attempt ends
  `NOT_APPLICABLE`, needs no decision), automatic retry for exactly the
  predecessor outcome slot A produces (`FAILED`), an explicit delay of 30
  seconds, and the fixed `require_fresh_availability_observation_for_unavailable`
  preserved. `ApplicationConfig()` is **not** changed: its default policy
  (`maximum_attempts_per_slot=1`, no automatic-retry states, delay 0) denies
  every retry at the attempt-budget and terminal-state gates, which Task 7's
  negative control asserts. **`other_config`** differs from `ApplicationConfig()`
  in one bounded `scheduler.retry` field so that C-32's disagreeing snapshot
  differs in both the base hash and the derived policy.
- **`supervised_draft(config, adapter_name)`** is the supervised flow's draft
  (Task 7): one slot, `SLOT_A` at ordinal 0, whose adapter is the selected
  Stage 6 row's `adapter_name` at `FAKE_ADAPTER_VERSION` with `FAKE_ENGINE` —
  the identities `supervised_catalog_entry_for(row.adapter_name)`
  (`doubles.supervision`) puts in the catalogue entry the supervised flow
  launches — and whose retry policy is the configuration-derived one.
  `SupervisedSqliteFlow` (§7.1.2) builds each `AdapterCommand` from that
  catalogue entry for the **run's** adapter identity, which `create_attempt`
  copies from the selected slot, and the fake adapter dispatches on the
  request's `adapter_name`; the shared alpha/beta slots of
  `config_backed_draft` therefore cannot drive a supervised row, and the two
  drafts stay distinct on purpose. With `material_base_configuration_hash(config)`
  the draft satisfies the queue-freeze kernel exactly as `config_backed_draft`
  does; nothing in the fake-adapter dispatcher, the catalogue or the production
  identities changes. Both drafts accept `strategy_version_hash` and
  `dataset_version_hash` keyword overrides (defaults: the doubles' constants),
  so a flow that registers a real `StrategyVersion` and `DatasetDescriptor`
  first can cite their `content_hash` values in the spec — the "resolve before
  queueing" reading of §3.3.1 — while the two-slot flow and C-32 keep the
  constants.

Planning evidence: the fence was executed unchanged against the committed
models before the plan was reviewed — the constructor probe (validators,
hashes, the queue-freeze kernel, the pure retry gates) and the application-flow
probe (the two-slot flow of Task 7 through the committed operations over the
in-memory unit of work to final aggregation, plus its two negative controls),
both under `.superpowers/sdd/stage8/probes/` and launched through the
`pytest-focused` profile; they prove constructor validity and application-flow
reachability only, never a SQLite behaviour.

```python
"""Pure fixture constructors of Stage 8 plan section 7.1.1."""

from __future__ import annotations

from typing import Final

from contract.harness import FAKE_ADAPTER_VERSION, FAKE_ENGINE
from crypto_lab.configuration.models import (
    ApplicationConfig,
    RetryConfig,
    SchedulerConfig,
)
from crypto_lab.configuration.retry_policy import retry_policy_from_config
from crypto_lab.configuration.snapshot import material_base_configuration_hash
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.experiment import (
    AdapterIdentity,
    EngineIdentity,
    ExperimentRecord,
    ExperimentSpec,
    ExperimentSpecDraft,
    SelectedEngineSlot,
    build_experiment_spec,
)
from crypto_lab.domain.lifecycle import ExperimentState, RetryTerminalState
from doubles.experiments import (
    DATASET_HASH,
    EXPERIMENT_ID,
    INSTANT,
    MATERIAL_HASH,
    SLOT_A,
    SLOT_C,
    STRATEGY_HASH,
    sample_draft,
    sample_experiment,
    sample_slot_compatibility,
    sample_slots,
)

#: The third slot's identities: the pair the Stage 5 in-memory flow uses for its
#: third slot. Distinct from (adapter.alpha 1.0.0, engine.alpha 2.3.4) and
#: (adapter.beta 1.2.0, engine.beta 2.3.4) under the validator key
#: (adapter_name, adapter_version, engine_name, engine_version).
ADAPTER_GAMMA: Final = AdapterIdentity(
    adapter_name="adapter.gamma", adapter_version="3.0.0"
)
ENGINE_GAMMA: Final = EngineIdentity(engine_name="engine.gamma", engine_version="1.0.0")
THIRD_SLOT: Final = SelectedEngineSlot(
    logical_slot_id=SLOT_C,
    slot_ordinal=2,
    adapter=ADAPTER_GAMMA,
    engine=ENGINE_GAMMA,
)


def three_slot_draft() -> ExperimentSpecDraft:
    """The shared two slots plus ``THIRD_SLOT`` (C-28)."""
    return sample_draft(selected_engine_slots=(*sample_slots(), THIRD_SLOT))


def three_slot_experiment(
    state: ExperimentState, *, experiment_id: str = EXPERIMENT_ID
) -> ExperimentRecord:
    """A QUEUED-or-later record over ``three_slot_draft`` with aligned compatibility."""
    draft = three_slot_draft()
    return sample_experiment(
        state,
        experiment_id=experiment_id,
        draft=draft,
        slot_compatibility=sample_slot_compatibility(draft),
    )


def other_spec() -> ExperimentSpec:
    """One non-slot field changed (LEVEL_2 -> LEVEL_1); slots unchanged."""
    return build_experiment_spec(
        sample_draft(comparison_level=ComparisonLevel.LEVEL_1), MATERIAL_HASH, INSTANT
    )


def other_slots_spec() -> ExperimentSpec:
    """The slot set changed; for DRAFT records only (no slot_compatibility)."""
    return build_experiment_spec(three_slot_draft(), MATERIAL_HASH, INSTANT)


def config_backed_draft(
    config: ApplicationConfig,
    *,
    strategy_version_hash: str = STRATEGY_HASH,
    dataset_version_hash: str = DATASET_HASH,
) -> ExperimentSpecDraft:
    """The shared draft carrying the configuration-derived retry policy."""
    return sample_draft(
        strategy_version_hash=strategy_version_hash,
        dataset_version_hash=dataset_version_hash,
        retry_policy=retry_policy_from_config(config.scheduler.retry),
    )


def config_backed_spec(config: ApplicationConfig) -> ExperimentSpec:
    """A spec whose configuration_hash and retry_policy agree with the snapshot."""
    return build_experiment_spec(
        config_backed_draft(config), material_base_configuration_hash(config), INSTANT
    )


def supervised_draft(
    config: ApplicationConfig,
    adapter_name: str,
    *,
    strategy_version_hash: str = STRATEGY_HASH,
    dataset_version_hash: str = DATASET_HASH,
) -> ExperimentSpecDraft:
    """One slot naming the scenario adapter at the fake catalogue's identities."""
    return sample_draft(
        strategy_version_hash=strategy_version_hash,
        dataset_version_hash=dataset_version_hash,
        selected_engine_slots=(
            SelectedEngineSlot(
                logical_slot_id=SLOT_A,
                slot_ordinal=0,
                adapter=AdapterIdentity(
                    adapter_name=adapter_name, adapter_version=FAKE_ADAPTER_VERSION
                ),
                engine=FAKE_ENGINE,
            ),
        ),
        retry_policy=retry_policy_from_config(config.scheduler.retry),
    )


def other_config() -> ApplicationConfig:
    """ApplicationConfig() with one bounded scheduler.retry field changed (C-32)."""
    return ApplicationConfig(
        scheduler=SchedulerConfig(retry=RetryConfig(maximum_attempts_per_slot=2))
    )


def retrying_config() -> ApplicationConfig:
    """The smallest explicit configuration that admits Task 7's one successor."""
    return ApplicationConfig(
        scheduler=SchedulerConfig(
            retry=RetryConfig(
                maximum_attempts_per_slot=2,
                automatically_retry_terminal_states=(RetryTerminalState.FAILED,),
                retry_delay_seconds=30,
            )
        )
    )
```

#### 7.1.2 The supervised SQLite composition (single authority)

`SupervisedSqliteFlow` (`tests/persistence_support/supervised.py`, Task 7) is a
**test-support composition helper**: it drives the eight selected Stage 6
scenario rows below through the production supervisor with every
persistence-dependent component bound to one SQLite test database. It is not a
production service, not a replacement supervisor, not a second protocol parser
or semantic reconciler, not a generic interchangeable-backend harness, not a
CLI composition feature, and **not a subclass of `OfflineCommandHarness`** — it
overrides none of that class's private unit-of-work, seed or inspector members
and edits neither `tests/contract/*` nor `tests/doubles/*`. It re-composes, in
test code, what `supervised_strategy.py::ProductionSupervision.supervise`
composes over the in-memory store (lifecycle, request material, command paths,
command, tee controller, recording observer, cancellation token, supervisor,
`invoke`, then the parse and semantic-outcome epilogue), with the storage seam
replaced. What it reuses unchanged: the Stage 6 scenario table
(`contract.scenarios.SCENARIOS`, its row identities and expected outcomes),
the fake executable and its launch identities
(`doubles.supervision.supervised_catalog_entry_for`, which resolves the Stage 6
fake `tests/fake_adapters/fake_adapter.py` for these rows at
`FAKE_ADAPTER_VERSION`/`FAKE_ENGINE`), the canonical builders
(`doubles.experiments`, the §7.1.1 fence), the command-path and catalogue
contracts, and the production supervision and application components in the
binding table. What it never imports, constructs or reaches:
`OfflineCommandHarness`, `InMemoryBackingStore`, `InMemoryUnitOfWork`,
`SeedingDiagnosticRecorder`, `InMemoryReconciliationSource`, any `.store`
attribute, a shadow replica, or a fallback to memory when a SQLite step is
inconvenient — Task 7's boundary review pins this with an AST scan of
`supervised.py`'s imports and attribute names. Process-local state stays where
its contract puts it: the supervisor's monotonic clock, the observer's trace,
the cancellation token and the parser state.

**Import routes (source-verified at the planning base).** `contract.scenarios`
and `contract.harness` are modules of the `contract` package
(`tests/contract/__init__.py`), `doubles.supervision` and `doubles.experiments`
of the `doubles` package; `persistence_support` is Task 1's package. All
resolve with `tests/` on `sys.path`, which pytest's prepend import mode
establishes for every module collected under `tests/` (`tests/conftest.py`
lives in a directory without `__init__.py`, so its directory is inserted) —
the same mechanism the Stage 7 suites rely on for `contract.harness` and
`doubles.*`. `tests/integration/persistence/test_stage8_supervised_flow.py` and
`supervised.py` therefore import them without any `pythonpath`, conftest,
launcher or package-configuration change. The two sibling-only modules of
`tests/integration/process_supervision/` (`supervised_strategy.py`,
`supervision_scenarios.py`, importable only from their own directory) are not
imported: the strategy they hold is the in-memory binding this composition
replaces and the platform rows are Stage 7's own. Production modules are
imported from `crypto_lab.*` directly.

**Binding table.** "Status" is one of: *existing* (source-verified at the
planning base), *planned* (a Stage 8 interface of the named task), *future
acceptance* (the SQLite behaviour Task 7 asserts; not executed during
planning). Every persistence-dependent row binds to the one test database.

| Component | Symbol and contract | Module (task) | Inputs → returns | Persistence dependency and transaction owner | Status |
|---|---|---|---|---|---|
| Test database | `open_test_database(tmp_path / "db", clock=clock)` → `SqliteDatabase` at `tmp_path/db/registry.sqlite3`; the supervision root is `tmp_path / "supervision"`, a sibling directory, so no command root, work directory, request or output path lies under the database directory and the fake adapter receives only `AdapterCommand` paths under the supervision root — never the database path or a handle | `persistence_support.harness` (Task 2), `crypto_lab.persistence.migration_runner` (Task 2) | a directory → the migrated database | the file itself | planned |
| Unit-of-work factory | `counting = CountingUnitOfWork(SqliteUnitOfWork(database, clock))`; `begin() -> SqliteTransaction` | Task 4, Task 6 | — | every application operation runs `run_operation` over `counting`; the flow itself opens transactions only for the registry, freeze and observation writes and for reads | planned |
| Application clock and identity | `clock = FixedClock(INSTANT)` for the operations and the lifecycle; `identity = SequentialIdentitySource("stage8-supervised")`; the supervisor's own clock is `RealtimeMonotonicClock(INSTANT)` (deadlines need monotonic progress, as in `ProductionSupervision`) | `doubles.experiments`, `doubles.supervision` | — | none | existing |
| Diagnostic recorder | `recorder = SqliteDiagnosticRecorder(database, clock)`; `record(diagnostic) -> Result[None]` | Task 3 | one `Diagnostic` → `Success(None)` | its own autonomous transaction per call (§4.4) | planned |
| Lifecycle | `Stage5InvocationLifecycle(unit_of_work=counting, clock=clock, diagnostics=recorder)`; `register_request_material(invocation_id, material)` | `crypto_lab.experiments.supervision_lifecycle` (existing; first composed over SQLite in Task 5) | the supervisor's port | short transactions inside each lifecycle call, never across the child | existing over planned |
| Registries | `transaction.strategy_versions.register(sample_strategy_version())`, `transaction.datasets.register(*sample_dataset_with_partitions())`, then `get_by_hash` round trips in a fresh session | Task 3 (`registries.py`, §7.1 builders), Task 4 (`SqliteTransaction` members) | records → `Result[None]` | one committed `counting.begin()` transaction | planned |
| Experiment | `create_experiment(ExperimentCreationRequest(spec_draft=supervised_draft(config, row.adapter_name, strategy_version_hash=version.content_hash, dataset_version_hash=descriptor.content_hash), material_base_configuration_hash=material_base_configuration_hash(config)))` → `transition_experiment(→ VALIDATED)` → `transaction.configuration_snapshots.freeze(experiment_id, snapshot_configuration(config))` (its own committed transaction) → `queue_experiment(ExperimentQueueRequest(expected_revision=1, config_derived_retry_policy=retry_policy_from_config(config.scheduler.retry), material_base_configuration_hash=material_base_configuration_hash(config), slot_compatibility=sample_slot_compatibility(draft)))` — one experiment per row that needs a run, one slot `SLOT_A` naming the row's adapter | `crypto_lab.experiments.experiment_service` (existing); freeze Task 3/4; `supervised_draft` §7.1.1 | → `QUEUED` at revision 2 | each operation's own `run_operation` transaction; the freeze's own | existing over planned |
| Attempt and its token | `create_attempt(AttemptCreationRequest(experiment_id, logical_slot_id=SLOT_A, expected_experiment_revision, request_hash=request_material_hash(experiment=…, logical_slot_id=SLOT_A, attempt_number=1, negotiated=DEFAULT_NEGOTIATED, limits=PROTOCOL_LIMITS_DEFAULT)))` → `AttemptCreation(experiment, attempt, attempt_token: AttemptTokenMaterial)`; the raw token is held in the flow's memory for the request material only (no column, snapshot member or detail ever carries it; only `attempt_token_hash` is stored) | `crypto_lab.experiments.run_service`, `crypto_lab.adapters.envelopes`, `contract.harness.DEFAULT_NEGOTIATED`, `crypto_lab.adapters.limits.PROTOCOL_LIMITS_DEFAULT` | → run `PENDING` attempt 1, experiment `RUNNING` | `run_operation` | existing |
| Run edges before a child | `transition_run(→ VALIDATING)`; for `RUN` rows `transition_run(→ READY, availability_observation_id=AVAIL_A)` — the plan-11.3 shortcut the Stage 7 harness's `ready` also takes for run rows, consuming the observation S-1 persisted | `crypto_lab.experiments.run_service` | — | `run_operation`; the `READY` row's foreign key to `runtime_availability_observations` holds because S-1 ran first | existing over planned |
| Availability observation | `describe_availability_observation(adapter_name=entry.adapter_name, adapter_version=entry.adapter_version, verdict=…, primary_code=…, descriptor=reconciliation.descriptor, observation_id=AVAIL_A, executable_path=entry.executable_path, executable_hash=entry.executable_hash, runtime_version=FAKE_RUNTIME_VERSION, operating_system=FAKE_OPERATING_SYSTEM, observed_at_utc=now, expires_at_utc=now + OBSERVATION_VALIDITY)` → `transaction.availability_observation_writer.add(observation)`; read back by `transaction.availability_observations.get(AVAIL_A)` | `crypto_lab.adapters.negotiation` (existing), `contract.harness` constants (existing), Task 3 writer and reader | the describe reconciliation → one row | one committed transaction | existing over planned |
| Invocation | `create_invocation(InvocationCreationRequest(command_kind, adapter_name, adapter_version, request_hash, timeout_seconds=row.timeout_seconds[, run_id, expected_run_revision]))`; `request_hash` is `request_hash_of(DescribeRequestPayload(...))` for `DESCRIBE` (the payload of `contract.harness.OfflineCommandHarness.describe`, rebuilt from `CORE_PROTOCOL_SUPPORT` and the catalogue entry) and `run.request_hash` otherwise | `crypto_lab.experiments.invocation_service`, `crypto_lab.adapters.envelopes`, `crypto_lab.adapters.negotiation.CORE_PROTOCOL_SUPPORT` | → `PENDING` invocation | `run_operation` | existing |
| Request material | `RequestMaterial(describe_payload=payload)` for `DESCRIBE`; `RequestMaterial(token=AttemptTokenMaterial(run_id=run.run_id, attempt_token=<held token>), negotiated_versions=DEFAULT_NEGOTIATED, limits=PROTOCOL_LIMITS_DEFAULT)` for `VALIDATE`/`RUN` | `crypto_lab.experiments.supervision_lifecycle`, `crypto_lab.domain.engine_run` | registered on the lifecycle before `invoke` | none | existing |
| Command paths and command | `paths = plan_command_paths(str(supervision_root), command_kind=kind, invocation_id=…, run_id=…)`; `AdapterCommand(command_kind=kind, catalog_entry=supervised_catalog_entry_for(row.adapter_name), invocation_id=…, request_path=paths.request_path, timeout_seconds=row.timeout_seconds, work_dir=paths.work_dir, result_path=paths.result_path)` for `RUN`, `output_path=paths.output_path` otherwise | `crypto_lab.process_supervision.roots`, `crypto_lab.adapters.commands`, `doubles.supervision` | pure | none | existing |
| Supervisor and controller | `build_supervisor(lifecycle=lifecycle, controller=TeeController(WindowsProcessController()), clock=RealtimeMonotonicClock(INSTANT), supervision_root=str(supervision_root), supervisor_instance_id=SCRIPTED_SUPERVISOR_INSTANCE_ID, cancellation_grace_seconds=1, describe_limits=PROTOCOL_LIMITS_DEFAULT, preflight=MISSING, observers=(observer, sampler))` → `WindowsProcessSupervisor`; `asyncio.run(supervisor.invoke(command, cancellation))` with `cancellation = ThreadSafeCancellationToken()` (the supervisor's `invoke(command, cancellation)` parameter; distinct from the attempt `token` of the epilogue row) → `Result[SupervisionOutcome]` (`command_result`, `output_parse`, `protocol_summary`, `stdout_byte_count`, `replay_count`, `executable_observation`, `trace`) | `doubles.supervision`, `crypto_lab.process_supervision.{supervisor,windows_process,cancellation,models}` | the command → the outcome | the lifecycle's short transactions only; the flow holds **no** transaction during `invoke` | existing |
| Observer hooks | `observer = RecordingObserver()`; S-6: `observer.on(EVENT_ACCEPTED, hook)` requests cancellation on the first `HEARTBEAT` (`entry.facts.get("event_type") == "HEARTBEAT"`), as the production strategy does; the transaction sampler: a second `RecordingObserver` whose hooks on `LAUNCHED`, `RUNNING_COMMITTED`, `EVENT_ACCEPTED`, `HEARTBEAT_MISSED` and `EXIT_REAPED` read `counting.open_now` and keep the maximum as `flow.max_open_during_child` | `doubles.supervision`, `crypto_lab.process_supervision.models.SupervisionTraceKind` | — | none (reads an integer) | existing |
| Epilogue parse | `EXITED` only: `VALIDATE` → `parse_validation_result(output_bytes, max_bytes=MAX_VALIDATION_RESULT_BYTES, token=token)`; `RUN` → `parse_result_manifest(manifest_bytes, max_bytes=PROTOCOL_LIMITS_DEFAULT.max_manifest_bytes, token=token)` and `CandidateObservation(relative_path, observed_size_bytes, observed_sha256=sha256_bytes(content), contains_attempt_token=token_present((content,), token))` for each declared path (`protocol_summary.artifact_declarations` plus a success manifest's `candidate_artifacts`) whose file exists under `paths.work_dir`; `DESCRIBE` → `parse_bootstrap_descriptor(output_bytes, max_bytes=MAX_DESCRIPTOR_OUTPUT_BYTES)` and `reconcile_describe(invocation, parse, outcome.stdout_byte_count, catalog_entry=entry, now_utc=now)` | `crypto_lab.adapters.{manifests,reconciliation,negotiation,sanitization,limits}`, `crypto_lab.domain.hashing` | files → typed parses | none | existing |
| Semantic outcome | `apply_command_semantic_outcome(SemanticOutcomeRequest(invocation_id, expected_invocation_revision, run_id, expected_run_revision, parsed_output, protocol_summary=outcome.protocol_summary, candidate_observations, negotiated_versions=DEFAULT_NEGOTIATED), unit_of_work=counting, clock=clock)` → `SemanticOutcome(invocation, run, reconciliation)`; then `recorder.record(d)` for every `reconciliation.diagnostics` (the caller obligation of §1.4 row 7) | `crypto_lab.experiments.semantic_outcome` | `EXITED` `VALIDATE`/`RUN` → the run's semantic terminal or `READY`/`RUNNING` | `run_operation` | existing over planned |
| Describe enrichment | `recorder.record(d)` for `reconcile_describe`'s diagnostics, then `enrich_invocation(InvocationEnrichmentRequest(invocation_id, expected_revision, additional_diagnostic_ids=sorted ids), unit_of_work=counting, clock=clock)` | `crypto_lab.experiments.invocation_service` | — | `run_operation` | existing over planned |
| Authoritative post-operation reads | a **fresh** `SqliteUnitOfWork(database, clock).begin()` opened after the writer's operation returned: `command_invocations.get`, `engine_runs.get`, `engine_runs.list_events(invocation_id)`, `diagnostics.get_many`, `availability_observations.get(AVAIL_A)`, then `rollback()`; `database.consistency_report()`; an independent stdlib connection `raw_connection(database.path)` counting `command_invocations`/`run_events` rows; `file_sha256(database.path)` before and after a row; `database.close()` then `open_test_database(tmp_path / "db")` for the reopen case | Tasks 1–4 | — | read-only sessions | planned / future acceptance |
| Reconciliation over the reopened file (S-8) | `reconcile_invocations(source=SqliteReconciliationSource(reopened, clock), lifecycle=Stage5InvocationLifecycle(unit_of_work=SqliteUnitOfWork(reopened, clock), clock=clock, diagnostics=SqliteDiagnosticRecorder(reopened, clock)), controller=WindowsProcessController(), preflight=PathPreflight(supervision_root=str(supervision_root), long_paths_supported=False, directory_ceiling=247, file_ceiling=259, probed_at_utc=INSTANT), clock=clock, supervisor_instance_id=SCRIPTED_SUPERVISOR_INSTANCE_ID, observer=MISSING)` → `ReconciliationReport(entries=…)` (the `PathPreflight` shape the Stage 7 restart tests build) | `crypto_lab.process_supervision.reconciliation` (existing), Task 5 source | — | read-only source; the lifecycle's own transactions | existing over planned |

**The eight selected cases.** Each row keeps its Stage 6 identity and
expected outcome (`contract.scenarios`, columns `invocation_state`,
`run_state`, `verdict`, `primary_code`, `accepted_events`, `native_exit`,
`timeout_seconds`); the plan states only the storage-specific obligations and
never restates the expected-result logic of the operations under test. Every
row: request material registered before `invoke`; the tee, observer and token
per command; the database untouched by the child (its path is never in an
`AdapterCommand`); after the writer's last operation a fresh session verifies
the rows; command roots removed by the supervisor's cleanup and the flow's
`finally:`; every launched child terminated and awaited (the Stage 7
discipline). A returned `SupervisionOutcome` is never counted as persistence
proof — only the fresh reads are.

| Case | Stage 6 row (`Scenario.name`, adapter) | Durable setup | Supervisor invocation and epilogue | Expected states (from the row) | Verified through fresh SQLite reads |
|---|---|---|---|---|---|
| S-1 | `row01-conformant-describe` (`fake.conformant`, `DESCRIBE`) | none (a describe has no run); the catalogue entry from `supervised_catalog_entry_for` | `DESCRIBE` invocation → `invoke` → `parse_bootstrap_descriptor` → `reconcile_describe` → record its diagnostics (none for the conformant row) → `enrich_invocation` if any → `describe_availability_observation(..., observation_id=AVAIL_A)` → writer `add` | invocation `EXITED`, verdict `DESCRIBED` | the invocation row `EXITED`; `availability_observations.get(AVAIL_A)` equal to the minted observation (`available`, adapter/version/executable hash of the entry); `run_facts`-free (`run_id` `MISSING`) |
| S-2 | `row02-conformant-validate` (`fake.conformant`, `VALIDATE`) | registries; experiment (freeze, queue); attempt 1; `→ VALIDATING` | `VALIDATE` invocation → `invoke` → `parse_validation_result` → `apply_command_semantic_outcome` → record reconciliation diagnostics (none) | invocation `EXITED` (exit 0), run `READY`, verdict `VALIDATED_READY`, 2 accepted events | invocation `EXITED` with `native_exit_value 0`; run `READY` with `availability_observation_id == AVAIL_A` (the foreign key held); `list_events` = 2, in sequence order, equal to `command_result.accepted_events` |
| S-3 | `row03-conformant-run` (`fake.conformant`, `RUN`) | as S-2 through `→ VALIDATING`, then `→ READY` with `AVAIL_A` (no validate child for a run row) | `RUN` invocation → `invoke` (linked launch and start inside the lifecycle) → `parse_result_manifest` → candidate observations → `apply_command_semantic_outcome` (`RESULT_FINALIZATION_ELIGIBLE`, manifest status `SUCCEEDED`) → record diagnostics (none) | invocation `EXITED` (0), run stays `RUNNING`, 5 accepted events; no finalization, no `RunManifest`, no success state | invocation `EXITED`, `process_created`, exit 0; run `RUNNING` (unchanged by the eligible verdict); `list_events` = 5 with contiguous sequence numbers equal to the accepted ledger; the raw token absent from every `TEXT` column and JSON snapshot; **the memory-bound negative control**: `raw_connection(database.path)` counts one invocation row and five event rows for this invocation, and `file_sha256(database.path)` differs from the pre-row hash — a writer or reader bound to memory would leave the file's rows unchanged while both in-process sides agreed |
| S-4 | `row05-unsupported-capability-validate` (`fake.unsupported-capability`, `VALIDATE`) | as S-2 | `VALIDATE` → `invoke` (exit 20) → `parse_validation_result` → `apply_command_semantic_outcome` → record the `COMPAT.NOT_APPLICABLE` primary | invocation `EXITED` (20), run `NOT_APPLICABLE`, verdict `NOT_APPLICABLE` | run `NOT_APPLICABLE` with its `primary_terminal_diagnostic_id` resolving through `diagnostics.get`; `dangling_diagnostic_references == 0` after the record — the same run edge the two-slot flow's slot B takes, here produced by the real supervisor and semantic outcome |
| S-5 | `row28-exit-40-run` (`fake.exit-40`, `RUN`) | as S-3 | `RUN` → `invoke` (exit 40) → manifest parse → `apply_command_semantic_outcome` (verdict `FAILED`, manifest status `FAILED`) → record the `ENGINE.RUNTIME_FAILURE` primary | invocation `EXITED` (40), run `FAILED`, 2 accepted events | run `FAILED` (a non-success terminal) with a resolving primary; `list_events` = 2; `dangling_diagnostic_references == 0` |
| S-6 | `row27-cancellation-run` (`fake.cancellation`, `RUN`, `cancel_after_first_heartbeat`) | as S-3 | `RUN` → the heartbeat hook calls `cancellation.request_cancellation()` → the supervisor interrupts, terminates and reaps → the lifecycle's `record_terminal` (core-won; no epilogue, no semantic outcome) | invocation `CANCELLED`, run `CANCELLED`, primary `PROCESS.CANCELLED` | invocation `CANCELLED` with `cleanup_complete`; run `CANCELLED` with the primary resolving (recorded by the lifecycle through `SqliteDiagnosticRecorder`, referrer-first, `causal_edge_mismatches == 0`) |
| S-7 | `row26-process-timeout-run` (`fake.process-timeout`, `RUN`, `timeout_seconds = 1`) | as S-3 | `RUN` → the deadline fires → forced termination → `record_terminal` (core-won) | invocation `TIMED_OUT`, run `TIMED_OUT`, primary `PROCESS.RUN_TIMED_OUT` | invocation `TIMED_OUT` with `cleanup_complete` and no `native_exit_value`; run `TIMED_OUT` with the primary resolving; the diagnostic row present in a fresh session |
| S-8 | the reopen case (no new row) | S-1–S-7 complete | `flow.close()` disposes the engine, drops every unit of work, lifecycle, recorder and record object; `SupervisedSqliteFlow.reopen(tmp_path)` opens the same file with `open_test_database` | — | every S-1–S-7 assertion re-read from the reopened file with new objects; `consistency_report()` with all eight counts zero (every experiment was queued through `queue_experiment` after a freeze); `reconcile_invocations` over `SqliteReconciliationSource` returns `entries == ()` (every invocation is terminal with cleanup complete, so the source lists no target); `run_states().isdisjoint(SUCCESS_ENGINE_RUN_STATES)`; `quick_check` = `ok` |

**Transaction boundaries.** The flow opens a transaction only for the
registry writes, the freeze, the observation write and its own reads, and
closes each before the next step; every application operation owns its
`run_operation` transaction; the lifecycle's transactions are per call; no
transaction is open while `invoke` awaits the child, while the child's output
is hashed or parsed, or while a command root is cleaned — `max_open_during_child == 0`
is asserted for every row, and `counting.max_open == 1` over the whole flow.

### 7.2 Disposition of every `harness`-parametrized contract case (Task 4)

`harness` becomes `@pytest.fixture(params=["in_memory", "sqlite"])`; the
`"sqlite"` branch returns `SqliteHarness(open_test_database(tmp_path, …))` and
closes it. Each existing case is classified once:

| Case (`tests/unit/experiments/test_port_contracts.py`) | Disposition |
|---|---|
| `test_get_missing_is_an_invariant_failure_on_every_repository` | runs unchanged |
| `test_add_then_get_round_trips_and_a_duplicate_identity_conflicts` | runs unchanged |
| `test_compare_and_swap_succeeds_only_at_the_expected_revision` | runs unchanged: the stale call `compare_and_swap(stored.revision + 1, replacement)` is refused at §4.3.1 step c (the pre-read finds `stored.revision`), not at step d, although the replacement's revision also fails the step; the row is unchanged and the following swap at `stored.revision` succeeds |
| `test_compare_and_swap_rejects_a_missing_row_and_a_wrong_revision_step` | runs unchanged: the first call is step b (no row); after the transaction's own `add(stored)` the pre-read reads that insert, step c passes and the two step violations are refused at step d with no `UPDATE` issued, so `get` returns `stored` |
| `test_run_and_invocation_compare_and_swap_share_the_contract` | runs with parents seeded (`put_lifecycle_parents(harness)` before `_put_run`; `_bump_run` targets `VALIDATING`, which carries no observation); both stale calls are step c refusals |
| `test_the_attempt_unique_index_rejects_a_second_attempt_one_for_the_slot` | runs with parents seeded (experiment; slots `SLOT_A` and `SLOT_B` come with it) |
| `test_latest_attempt_is_missing_for_an_unattempted_slot_and_highest_otherwise` | runs with parents seeded (experiment, and `AVAIL_A` because `sample_run(_R.FAILED)` is an observed state) and **one reordering**: the initial attempt is inserted before its successor, because the successor's `predecessor_run_id` foreign key forbids the reverse order; the case still proves `latest_attempt` is the highest attempt and `count_attempts` counts both, and the comment is updated |
| `test_the_invocation_index_permits_one_non_terminal_invocation_per_run_and_kind` | runs with parents seeded (`run=True`) |
| `test_list_for_run_is_ordered_by_creation_then_identifier_regardless_of_insertion` | builds its own in-memory harness per permutation today; Task 4 rewrites it to build the parametrized harness's kind per permutation (a `harness_factory` fixture) and seeds `run=True` in each |
| `test_insert_if_absent_inserts_once_and_then_returns_the_stored_winner` | runs with parents seeded (experiment and the predecessor run `RUN_ID`; the sample decision is `DENIED` after `FAILED` and references no observation) |
| `test_diagnostic_reader_offers_primitive_reads_only` | runs unchanged |
| `test_list_for_adapter_filters_on_the_three_keys_and_sorts_by_identifier` | runs unchanged (nothing is pre-seeded; the identities it seeds are its own) |
| `test_list_for_adapter_is_unbounded_so_no_qualifying_observation_is_dropped` | runs unchanged (257 rows) |
| `test_rollback_restores_every_store_and_commit_publishes_all_or_nothing` | runs unchanged (it already inserts in foreign-key order; the peeking transaction is a WAL reader and sees nothing uncommitted) |
| `test_a_failed_second_write_leaves_the_first_undurable_after_rollback` | runs with three body edits: (1) `put_lifecycle_parents(harness, experiment_id=OTHER_EXPERIMENT_ID)` seeds the parent experiment (`QUEUED`, slots `SLOT_A`/`SLOT_B`) under `OTHER_EXPERIMENT_ID`, so the body's later `experiments.add(sample_experiment(_E.DRAFT))` (identity `EXPERIMENT_ID`) still inserts a new row and provisionally succeeds; (2) `stored_run = sample_run(_R.PENDING, experiment_id=OTHER_EXPERIMENT_ID)` so `_put_run` satisfies the `(experiment_id, logical_slot_id) → engine_slots` key; (3) the final assertions become `committed_experiments() == (sample_experiment(_E.QUEUED, experiment_id=OTHER_EXPERIMENT_ID),)` and `committed_engine_runs() == (stored_run,)`, plus `_code(fresh.experiments.get(EXPERIMENT_ID)) == INVARIANT_VIOLATION` on a fresh transaction. Walk-through: the seed is valid (the `QUEUED` parent under `OTHER_EXPERIMENT_ID` with its two slot rows; `RUN_ID` at revision 0 under it); the first write `experiments.add(sample_experiment(_E.DRAFT))` inserts `EXPERIMENT_ID` and its slot rows and is provisional (visible to this transaction only); the second write `engine_runs.compare_and_swap(stored_run.revision + 5, _bump_run(stored_run, _R.VALIDATING))` reaches the intended branch: §4.3.1 step a reads `stored_run` at revision 0, step c compares `0 != 5` and returns `CONF` — before step d, which would otherwise report the replacement's revision `1 != 6` as `INV`, and without issuing any `UPDATE`; the run row is untouched; `rollback()` then discards the provisional experiment and its slot rows; the fresh reader sees neither effect (`EXPERIMENT_ID` absent, the run still at revision 0) and both seed rows unchanged. The test remains a whole-operation rollback test: no repository savepoint is involved (both writes are single statements) and it is not turned into continuation-and-commit |
| `test_an_unfinished_transaction_never_reaches_a_rebuilt_unit_of_work` | runs unchanged; the dangling transaction holds only its own uncommitted insert, the rebuilt reader sees committed state, and the harness rolls the survivor back at teardown (§7.1) |
| `test_commit_detects_a_row_that_moved_since_the_transaction_began` | **split**: the first half (loser's stale CAS fails at the call after the winner commits) runs unchanged on both kinds (C-4); the second half (two open transactions both staging an insert of one identity, the later commit failing) is impossible over one SQLite writer and moves, verbatim, into `test_the_in_memory_unit_of_work_detects_a_racing_insert_at_commit` pinned to `InMemoryUnitOfWork`; its SQLite replacement is C-1 |
| `test_commit_rejects_distinct_identities_that_collide_on_a_unique_index` | **in-memory only** (both halves stage colliding inserts in two open transactions); renamed `test_the_in_memory_unit_of_work_rejects_index_collisions_at_commit`; SQLite replacements are C-2 and C-3 |
| `test_rebuilt_units_of_work_observe_committed_state_in_deterministic_order` | runs unchanged: its three experiments share `SLOT_A`/`SLOT_B`, which the composite `engine_slots` key of reading 7 admits (C-28 A) |
| `test_protocol_returns_are_immutable_projections_not_internal_collections` | runs with parents seeded (`run=True`) |
| new: `test_append_event_replays_identical_and_refuses_conflicting_content` and `test_list_events_is_sequence_ordered_and_empty_for_an_unknown_invocation` | added to the shared suite (both kinds) with `put_lifecycle_parents(harness, run=True, invocation=True)` first — the port's `append_event`/`list_events` had no harness case |
| hook cases, `test_the_in_memory_unit_of_work_lifecycle_is_explicit`, `test_an_exception_inside_the_context_manager_rolls_back`, `test_insert_if_absent_under_a_simulated_concurrent_winner_returns_the_winner`, `test_the_doubles_module_declares_no_thread_sleep_or_random_dependency` | in-memory only today; unchanged |

Edits to existing test bodies are exactly: the split, the rename, the
`harness_factory` rewrite, the parent-seeding calls listed above (each a
single `put_lifecycle_parents(...)` line before the first child insert), the
one reordering in `test_latest_attempt…`, and the three listed edits of
`test_a_failed_second_write…`; every other retained assertion keeps its bytes. The shared suite thereby becomes referentially complete for both kinds,
which is a truth about the ports (spec 23.3.1's restricted references), not an
isolation limitation copied from the double. The `PortHarness` protocol gains no
member. No observation is pre-seeded anywhere: `test_get_missing…` asserts
`avail_{UUID_A}` absent and `test_list_for_adapter_*` seed their own rows.

### 7.3 Codec and constraint properties (`tests/property/test_persistence_codecs.py`, Task 3)

Hypothesis strategies compose the doubles' `sample_*` builders with drawn
variations: every state of each lifecycle enum, each `MISSING`-typed field
present or absent where the state allows, `Decimal` magnitudes across the
canonical grammar (including `0`, long scales and negative values where a field
admits them), timestamps with and without microseconds, non-ASCII text in every
bounded text field, empty and maximal identifier tuples, every `RunEvent`
payload class, every `ArtifactOwnerRef` variant, and `Diagnostic.details`
documents at the depth, node and byte bounds. Properties (bounded examples,
`deadline=None` where a strict model is validated repeatedly):

- encode → decode is the identity for every record (equality of the canonical
  model, so `MISSING` and `[]` survive), and decode → encode reproduces the same
  column values;
- the canonical bytes of the decoded record equal those of the input;
- every timestamp round-trips to the exact microsecond and the column integer
  is monotone in the instant;
- every `NULL` column corresponds to a `MISSING` field and vice versa (no `null`
  appears in any encoded JSON snapshot at the top level);
- a mutated row (one column changed to an out-of-domain value) is refused on
  decode with `CORE.INVARIANT_VIOLATION` naming the table and identity;
- for a drawn acyclic batch of diagnostics (at most eight, each citing a drawn
  subset of the others) recorded through `SqliteDiagnosticRecorder` in a drawn
  order, the relation read by `causal_edges` equals the set of
  `(referrer, cause)` pairs of the batch and `causal_edge_mismatches` and
  `unresolved_causal_references` are both zero — the convergence of reading 23
  under every recording order, not only the Stage 7 one (Task 3);
- a `ConfigSnapshot` drawn from `ApplicationConfig` variations frozen through
  `SqliteConfigurationSnapshotWriter.freeze` on a `DRAFT` row is read back
  equal; a snapshot row with any one of its three data columns
  (`configuration_snapshot_json`, `configuration_audit_hash`,
  `material_base_configuration_hash`) altered is refused by `get` as
  `CORE.INVARIANT_VIOLATION`, while the fourth column
  `configuration_snapshot_schema_version` admits no other value — its
  `CHECK (col = '1.0.0')` and the whole-or-absent CHECK refuse the alteration at
  the `UPDATE` itself (`IntegrityError`, C-27's raw half), so `get` never sees
  it (Task 3).

### 7.4 Re-pointed Stage 5–7 suites

| Suite | Stage 8 treatment | Task |
|---|---|---|
| `tests/unit/experiments/test_port_contracts.py` | `"sqlite"` parameter (§7.2) | 4 |
| `tests/unit/experiments/test_supervision_lifecycle.py` | not edited; `tests/unit/persistence/test_sqlite_supervision_lifecycle.py` runs the named lifecycle scenarios over `SqliteUnitOfWork` + `SqliteDiagnosticRecorder`: the coupled terminal that records the primary first, the recorder failure that stops the write, the two `append_event` cases, the linked launch and start, the same-state replay, the external-winner alone and coupled paths, and the lost-swap paths | 5 |
| `tests/unit/process_supervision/test_restart_reconciliation.py` | not edited; `tests/integration/persistence/test_sqlite_restart_reconciliation.py` runs every `run_every_row` state over `SqliteReconciliationSource` after a close-and-reopen (C-23) | 5 |
| `tests/integration/experiments/test_stage5_in_memory_flow.py` | not edited; `tests/integration/persistence/test_stage8_durable_flow.py` runs the same flow over SQLite (§8, Task 7) | 7 |
| `tests/integration/process_supervision/test_supervised_contract_matrix.py` | not edited; Task 7 re-composes the eight selected Stage 6 rows of §7.1.2 (`contract.scenarios` rows 1, 2, 3, 5, 26, 27 and 28 plus the reopen case) through the production supervisor with every persistence component bound to the SQLite test database — `SupervisedSqliteFlow`, not the in-memory-bound `OfflineCommandHarness` or `ProductionSupervision` | 7 |

### 7.5 Windows platform cases (Task 1, 6)

- database paths with spaces and Unicode components under `tmp_path` open,
  migrate and round-trip (Task 1);
- a lock held by another process (C-17) and by another connection (C-15);
- a read-only file attribute (C-18);
- WAL sidecar files present after an interrupted writer (C-17) and after a
  clean `close()` (either absent or tolerated on reopen);
- an open handle held by the test's own raw connection or by an abandoned
  transaction makes `tmp_path` cleanup fail on Windows, so every fixture closes
  every raw connection in `finally:`, the harness rolls back every open
  transaction and disposes the engine in teardown (§7.1), and only then asserts
  that no `-wal`/`-shm` handle survives;
- no test relies on `PRAGMA locking_mode=EXCLUSIVE`, on file deletion while
  open, or on the exact SQLite error message text.

### 7.6 What Stage 8 tests never do

No `subprocess` import outside `tests/integration/persistence/test_wal_restart.py`;
no `os.system` text; no `time.sleep` for synchronization (only the two bounded
observation budgets of §5.3, asserted, never slept); no database outside
`tmp_path` or `:memory:`; no committed `.sqlite3`/`.db` fixture; no wall clock
(`FixedClock` everywhere); no engine or adapter beyond the Stage 6 fakes and the
Stage 7 fake script; no success run state and no `RunManifest`.

---

## 8. Task decomposition

Eight vertical tasks, sized by the dependency graph of §1.2 (database boundary
→ schema and migrations → codecs and registries → unit of work and lifecycle
repositories → recovery reads → concurrency evidence → composition → status).
No task depends on a file created by a later task. Each is test-first: focused
RED, minimum implementation, focused GREEN, then broader verification; each
ends in one commit and a clean worktree. Focused runs use the launcher
`pytest-focused` profile with `-o addopts=` (diagnostic only, no coverage
number). **Every task that creates a module under `src/crypto_lab`, first defines
a deferred name, first imports a new root or first imports an infrastructure
root in a module also edits the guard files exactly as §2.6 tabulates; those
edits are owned by the task and are not repeated in each file list, and each
such task's focused RED includes the §2.6 guard expectations for its own paths,
names, roots and pairs.** Every task's **Quality gates** are the launcher
`ruff-format-all` (apply the printed diff by hand), `ruff-check-all`, `mypy-all`
(strict, over `src`, `tests` and `scripts`) and `schema-generate-check`; from
Task 2 onward they include `migration-check`. Every task's **Schema and
migration preservation** is `schema-generate-check` clean on the unchanged
35-entry registry, `git diff --stat -- schemas/` empty, and (from Task 2)
`migration-check` green with exactly one head; every task's **Independent
review** is a fresh reviewer over the task's diff with the task's declared
readings listed; every task's **Clean-worktree checkpoint** is `git status
--short` empty after the commit with every guard edit inside it. Every RED
sketch below is judged as strict-mypy, ruff-clean code: explicit keywords,
`isinstance` narrowing of `Result` and `X | MISSING` values, `match=` on every
`pytest.raises(ValueError)`. Every step is a checkbox for the executor.

### Task 1 — Dependencies, the SQLite database boundary and failure mapping

**Objective.** Add `sqlalchemy` and `alembic` through the offline-first gates,
and deliver `SqliteDatabase` (engine, PRAGMA policy and read-back, connection
lifetime, read-only sessions, DBAPI-error classification, path composition,
identity and integrity checks) with the Stage 8 diagnostic table, proven by the
library probes of §2.8 and the cases C-15, C-16, C-19, C-20.
**Prerequisites.** Planning base merged; a fresh worktree synced with the
launcher `sync` profile.
**Files created.** `src/crypto_lab/persistence/database.py`,
`src/crypto_lab/persistence/diagnostics.py`,
`tests/persistence_support/__init__.py`,
`tests/persistence_support/harness.py` (`raw_connection`, `file_sha256`,
`accept_any_revision`, `ok`, `code` only; §7.1 ownership paragraph),
`tests/unit/persistence/conftest.py` (`fixed_clock` and the unmigrated
`bare_database`; §7.1 fixtures row),
`tests/unit/persistence/test_sqlite_database.py`,
`tests/unit/persistence/test_persistence_diagnostics.py`.
**Files modified.** `pyproject.toml` (two runtime dependencies), `uv.lock`
(regenerated by the launcher), `tests/safety/test_project_dependencies.py`
(`_EXPECTED_RUNTIME_REQUIREMENTS` 2 → 4, `_PROHIBITED_FAMILIES` 29 → 27 plus the
positive control), `tests/safety/test_gitnexus_development_tooling.py` (the
duplicate dependency list), `tests/safety/test_stage3_boundaries.py` (paths 95 →
97; root `sqlalchemy` 27 → 28), `tests/unit/test_package_layout.py` (95 → 97),
`tests/unit/process_supervision/test_supervisor_preflight.py` and
`tests/unit/process_supervision/test_restart_reconciliation.py` (the `95`/`27`
cross-pins), `tests/safety/test_stage5_boundaries.py` (the
`("persistence/database.py", "sqlalchemy")` exemption; the control rewritten to
iterate pairs with the three mirrors), `tests/safety/test_stage7_boundaries.py`
(retire the Stage 8 shape scan and its control; keep the deferred-name half under
`test_stage_nine_finalization_names_stay_deferred`),
`tests/architecture/test_package_import_boundaries.py` (the `persistence`
closure and its `domain`/`configuration` anchors),
`docs/development/verification.md` (the "Dependency changes" sentence: "…
networking client, or GitNexus; the Stage 8 SQLAlchemy and Alembic dependencies
were introduced through the approved Stage 8 acquisition gates and are the only
database stack.").
**Interfaces consumed.** `DatabaseConfig`, `Clock`, `Result`/`Success`/`Failure`,
`stage5_failure`, `Diagnostic`, `DiagnosticCategory`.
**Interfaces produced.**
`SqliteDatabase.open(path: Path, *, busy_timeout_ms: int, clock: Clock, revision_policy: Callable[[Connection], Result[None]]) -> Result[SqliteDatabase]`
(steps 1–5 of §6.2; `revision_policy` is applied as step 6 and is supplied by
Task 2's entry points; Task 1's tests pass an accepting policy);
`SqliteDatabase.connection() -> ContextManager[Connection]` (a pooled
connection with PRAGMAs verified; the unit of work's checkout);
`SqliteDatabase.read_only() -> ContextManager[Connection]`;
`SqliteDatabase.classify(error: DBAPIError) -> ErrorCode`;
`SqliteDatabase.failure(code, *, message, details) -> Failure`;
`SqliteDatabase.close() -> None`; `SqliteDatabase.path` (absolute);
`database_path(runtime_root: Path, config: DatabaseConfig) -> Path`;
`APPLICATION_ID: Final[int]`; in `diagnostics.py`: `STAGE8_DIAGNOSTIC_CODES`
(reading 9), `WRITE_FAILED`, `MIGRATION_MISMATCH`, `STORAGE_UNAVAILABLE`,
`persistence_failure(code, *, message, clock, details) -> Failure`; in
`tests/persistence_support/harness.py`: `raw_connection(path)`,
`file_sha256(path)`, `accept_any_revision(connection)`, and the two `Result`
narrowers `ok(result)` / `code(result)` that every later task's tests use
(written `_ok`/`_code` in the sketches, §7.1); in
`tests/unit/persistence/conftest.py`: the `fixed_clock` and `bare_database`
fixtures (§7.1).
**Owned schema/migration/configuration changes.** None (no table exists yet;
the probes create throwaway tables with `text()` DDL inside the test).
**Guard/dependency transitions.** §2.6: source files 95 → 97; roots 27 → 28;
exemption pairs 1 → 2; dependency pins; the Stage 7 negative retired; the
architecture closure added; §2.8 gates recorded (which of `lock-acquire`,
`sync-acquire` ran, and the exact resolved versions, in the ledger).

- [ ] **Step 1: Resolve and acquire through the exact offline-first gates**
  (§2.8, verbatim commands, human approval at each gate). Then run the lock
  review of §2.8 and record its findings.
- [ ] **Step 2: Focused RED.** Write the tests first:

```python
def test_database_path_is_a_pure_join_of_runtime_root_and_filename() -> None:
    config = DatabaseConfig()
    assert database_path(Path("C:/lab/runtime"), config) == Path(
        "C:/lab/runtime/crypto_lab.sqlite3"
    )
    with pytest.raises(ValueError, match="absolute"):
        database_path(Path("runtime"), config)


def test_open_applies_and_reads_back_every_pragma(tmp_path: Path) -> None:
    opened = SqliteDatabase.open(
        tmp_path / "x.sqlite3",
        busy_timeout_ms=100,
        clock=FixedClock(INSTANT),
        revision_policy=_accept,
    )
    assert isinstance(opened, Success)
    with opened.value.connection() as connection:
        assert _pragma(connection, "journal_mode") == "wal"
        assert _pragma(connection, "foreign_keys") == 1
        assert _pragma(connection, "synchronous") == 2
        assert _pragma(connection, "busy_timeout") == 100
    opened.value.close()


def test_open_never_creates_a_directory(tmp_path: Path) -> None:
    missing = tmp_path / "absent" / "x.sqlite3"
    opened = SqliteDatabase.open(
        missing, busy_timeout_ms=100, clock=FixedClock(INSTANT), revision_policy=_accept
    )
    assert _code(opened) == STORAGE_UNAVAILABLE
    assert not missing.parent.exists()


def test_a_held_writer_lock_fails_the_writer_as_a_bounded_conflict(
    bare_database: SqliteDatabase,
) -> None:
    # bare_database (§7.1): an unmigrated file opened with accept_any_revision;
    # the probe table is throwaway, so no Task 2 schema is needed here.
    holder = raw_connection(bare_database.path)
    try:
        holder.execute("BEGIN IMMEDIATE")
        started = time.perf_counter()
        with bare_database.connection() as connection:
            with pytest.raises(OperationalError) as caught:
                connection.execute(text("CREATE TABLE probe (x INTEGER)"))
        elapsed = time.perf_counter() - started
        assert bare_database.classify(caught.value) == CONCURRENCY_CONFLICT
        assert 0.05 <= elapsed < 2.0
    finally:
        holder.close()


def test_a_stale_snapshot_write_is_refused_immediately(
    bare_database: SqliteDatabase,
) -> None:
    with bare_database.connection() as setup:
        setup.execute(text("CREATE TABLE probe (x INTEGER PRIMARY KEY, y INTEGER)"))
        setup.execute(text("INSERT INTO probe VALUES (1, 0)"))
        setup.commit()
    with bare_database.connection() as reader:
        # The first statement autobegins the deferred transaction (§2.8 recipe).
        assert reader.execute(text("SELECT y FROM probe")).scalar_one() == 0
        other = raw_connection(bare_database.path)
        try:
            other.execute("UPDATE probe SET y = 1 WHERE x = 1")
            other.commit()
        finally:
            other.close()
        with pytest.raises(OperationalError) as caught:
            reader.execute(text("UPDATE probe SET y = 2 WHERE x = 1"))
        assert isinstance(caught.value.orig, sqlite3.Error)
        assert caught.value.orig.sqlite_errorcode == 517
        assert bare_database.classify(caught.value) == CONCURRENCY_CONFLICT
        # The refused statement did not end the transaction.
        assert reader.execute(text("SELECT y FROM probe")).scalar_one() == 0


def test_a_foreign_or_corrupt_file_is_refused_without_mutation(
    tmp_path: Path,
) -> None:
    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"not a database" * 64)
    before = file_sha256(corrupt)
    opened = SqliteDatabase.open(
        corrupt, busy_timeout_ms=100, clock=FixedClock(INSTANT), revision_policy=_accept
    )
    assert _code(opened) == STORAGE_UNAVAILABLE
    assert file_sha256(corrupt) == before


def test_the_stage_eight_code_table_is_closed_and_categorised() -> None:
    assert set(STAGE8_DIAGNOSTIC_CODES) == {
        "PERSISTENCE.CONCURRENCY_CONFLICT",
        "PERSISTENCE.WRITE_FAILED",
        "PERSISTENCE.MIGRATION_MISMATCH",
        "PERSISTENCE.STORAGE_UNAVAILABLE",
        "CORE.INVARIANT_VIOLATION",
    }
    for code, posture in STAGE8_DIAGNOSTIC_CODES.items():
        assert posture.category is (
            DiagnosticCategory.INTERNAL_INVARIANT
            if code.startswith("CORE.")
            else DiagnosticCategory.PERSISTENCE
        )
```

  plus: the `classify` table of §6.5 over synthesized DBAPI errors carrying each
  extended code; the unique/primary-key `IntegrityError` mapping; the
  foreign-key/CHECK/trigger mapping; `SQLITE_FULL` and `SQLITE_READONLY_*` →
  `WRITE_FAILED`; a refused `INSERT` followed by a successful `INSERT` and
  `COMMIT` on the same connection (the statement-level scope of §2.5 reading 3);
  a pooled connection re-used from a second thread keeps its PRAGMAs; a pool of
  one refuses a second checkout as `STORAGE_UNAVAILABLE` within the pool timeout
  (the pool's own timeout error, not a DBAPI error); a path with spaces and
  Unicode components opens; a
  foreign `application_id` is refused without mutation; `read_only()` performs
  no write (`total_changes` unchanged); a `quick_check` failure is
  `STORAGE_UNAVAILABLE`; the savepoint probe of §2.8 (`INSERT`, `SAVEPOINT`,
  `INSERT`, refused `INSERT`, `ROLLBACK TO`, `COMMIT` → only the first row
  durable); `test_the_respelled_codes_equal_the_stage_five_constants`
  (`WRITE_FAILED`-side table's `PERSISTENCE.CONCURRENCY_CONFLICT` and
  `CORE.INVARIANT_VIOLATION` literals equal
  `experiments.diagnostics.CONCURRENCY_CONFLICT`/`INVARIANT_VIOLATION`, the
  test importing both modules); and the §2.6 guard expectations (allowlist
  naming the two missing paths; roots naming `sqlalchemy`; the exemption pair;
  the dependency tuples; the retired Stage 7 test absent; the architecture
  closure present).
- [ ] **Step 3: Run the focused set and confirm every new test fails for the
  expected reason** (`ImportError` for the two `crypto_lab.persistence`
  modules, raised while collecting `tests/persistence_support/harness.py` and
  the conftest, which the task creates alongside the tests so that
  `bare_database`, `raw_connection` and `file_sha256` resolve; the dependency
  pins failing on the four-entry tuple; the Stage 7 shape scan failing on the
  new paths until retired).
- [ ] **Step 4: Minimum GREEN.** The two modules; the guard edits of §2.6 for
  this task.
- [ ] **Step 5: Focused GREEN.** `tests\unit\persistence tests\safety tests\architecture tests\unit\test_package_layout.py -q`.
- [ ] **Step 6: Lock review** (§2.8) recorded in the ledger: resolved versions,
  wheels, `py.typed`, no prohibited family; `mypy-all` green without overrides.
- [ ] **Step 7: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\safety tests\architecture tests\property`.
**Windows-specific tests.** Spaces and Unicode in the database path; the held
lock (C-15); read-only session on Windows handles.
**Minimum passing evidence.** The focused set green; `mypy-all`, `ruff-check-all`,
`ruff-format-all`, `schema-generate-check` green; `lock-check` and `sync` green
offline after the gates.
**Security and boundary review.** `persistence` imports no `sqlite3`, `os`,
`sys`, `time`; no configuration read; no directory creation; no SQL built from
row values; the raw token appears nowhere; no `experiments` module edited; the
acquisition profiles ran only after explicit approval and are recorded as
bootstrap evidence, never as verification.
**Independent review.** Declared readings: 3, 9; the two Stage 1 surfaces
amended (§1.6 item 9); the retired Stage 7 negative and its surviving half.
**Commit message.** `feat: add sqlalchemy and alembic with the sqlite database boundary`

### Task 2 — Relational schema, baseline migration, revision checks and the migration gate

**Objective.** Define the thirteen tables, constraints, indexes and triggers of
§3.3–§3.4 as declarative metadata (including the four configuration-snapshot
columns of `experiments`, the `diagnostic_causes` relation and the four
`experiments` triggers); ship the Alembic script directory with the
baseline revision; implement the revision-state vocabulary, the migration
runner, `open_database`/`open_for_migration`, `scripts/verify_migrations.py`,
the `migration-check` launcher profile and the verifier step; prove C-21, C-22,
C-27 and reading 16–17.
**Prerequisites.** Task 1.
**Files created.** `src/crypto_lab/persistence/schema.py`,
`src/crypto_lab/persistence/migration_runner.py`,
`src/crypto_lab/persistence/migrations/__init__.py`,
`src/crypto_lab/persistence/migrations/env.py`,
`src/crypto_lab/persistence/migrations/script.py.mako`,
`src/crypto_lab/persistence/migrations/versions/__init__.py`,
`src/crypto_lab/persistence/migrations/versions/r0001_stage8_baseline.py`,
`scripts/verify_migrations.py`, `tests/unit/persistence/test_sqlite_schema.py`,
`tests/unit/persistence/test_sqlite_migrations.py`,
`tests/unit/persistence/test_sqlite_constraints.py` (the raw-statement half of
C-27; Task 4 adds the repository half).
**Files modified.** `tests/persistence_support/harness.py` (adds
`open_test_database`, §7.1), `tests/unit/persistence/conftest.py` (adds the
migrated `sqlite_database`, `seeded_database` and
`two_revision_script_directory`; §7.1 fixtures row — `bare_database` stays for
Task 1's probes), `scripts/invoke-uv.ps1` (the `migration-check` clause),
`scripts/verify.ps1` (the step), `tests/safety/test_uv_launcher.py` and
`tests/safety/test_stage3_boundaries.py` (§2.6 launcher and verifier pins;
paths 97 → 103; root `alembic` 28 → 29), `tests/unit/test_package_layout.py`
(97 → 103), the two cross-pin files, `tests/safety/test_stage5_boundaries.py`
(seven exemption pairs), `docs/development/verification.md` ("Complete
verification" eleven steps; "Migration workflow" subsection describing the
script and profile), `README.md` ("The eleven-operation workflow …").
**Interfaces consumed.** `SqliteDatabase`, `classify`, `persistence_failure`,
every lifecycle enum, `RECOGNIZED_NATIVE_EXIT_VALUES`, `MAX_*` bounds of the
records.
**Interfaces produced.** `schema.metadata: MetaData`; one `*Row` declarative
class per table (`ExperimentRow`, `EngineSlotRow`, `EngineRunRow`,
`CommandInvocationRow`, `RunEventRow`, `RetryDecisionRow`,
`RuntimeAvailabilityObservationRow`, `DiagnosticRow`, `DiagnosticCauseRow`,
`StrategyVersionRow`, `DatasetRow`, `DatasetPartitionRow`, `ArtifactOwnerRow`);
`PARTIAL_INDEX_SQL`, `TRIGGER_SQL`, `EXPECTED_SCHEMA_OBJECTS` (the pinned
`sqlite_master` expectation); `RevisionState`, `RevisionReport`,
`expected_head()`, `check_revision(connection)`, `apply_migrations(database)`,
`metadata_drift(connection)`, `schema_objects(connection)`;
`open_database(path, *, busy_timeout_ms, clock) -> Result[SqliteDatabase]` and
`open_for_migration(...)` (§6.2, composing `SqliteDatabase.open` with the
revision policy; both in `migration_runner.py` so `database.py` never imports
Alembic); in `tests/persistence_support/harness.py`: `open_test_database`; in
`tests/unit/persistence/conftest.py`: the migrated `sqlite_database`,
`seeded_database` and `two_revision_script_directory` fixtures (§7.1).
**Owned schema/migration/configuration changes.** The whole baseline revision;
the launcher profile; the verifier step.
**Guard/dependency transitions.** §2.6: source files → 103; roots → 29;
exemption pairs → 9; launcher/verifier pins; doc step lists.

- [ ] **Step 1: Focused RED.**

```python
def test_the_script_directory_has_exactly_one_head_named_by_the_baseline() -> None:
    assert expected_head() == "r0001_stage8_baseline"


def test_every_revision_state_is_classified_and_refusals_do_not_mutate(
    tmp_path: Path,
) -> None:
    path = tmp_path / "x.sqlite3"
    empty = open_database(path, busy_timeout_ms=100, clock=FixedClock(INSTANT))
    assert _code(empty) == MIGRATION_MISMATCH
    assert not path.exists()
    migrating = open_for_migration(path, busy_timeout_ms=100, clock=FixedClock(INSTANT))
    assert isinstance(migrating, Success)
    applied = apply_migrations(migrating.value)
    assert isinstance(applied, Success)
    assert applied.value.state is RevisionState.CURRENT
    migrating.value.close()
    current = open_database(path, busy_timeout_ms=100, clock=FixedClock(INSTANT))
    assert isinstance(current, Success)
    current.value.close()
    stamp_unknown_revision(path, "zz_future")
    before = file_sha256(path)
    unknown = open_database(path, busy_timeout_ms=100, clock=FixedClock(INSTANT))
    assert _code(unknown) == MIGRATION_MISMATCH
    assert (
        _code(open_for_migration(path, busy_timeout_ms=100, clock=FixedClock(INSTANT)))
        == MIGRATION_MISMATCH
    )
    assert file_sha256(path) == before


def test_a_migrated_database_has_no_metadata_drift_and_the_pinned_objects(
    sqlite_database: SqliteDatabase,
) -> None:
    with sqlite_database.read_only() as connection:
        assert metadata_drift(connection) == ()
        assert schema_objects(connection) == EXPECTED_SCHEMA_OBJECTS


def test_a_failing_revision_rolls_back_to_the_prior_revision(
    tmp_path: Path, two_revision_script_directory: Path
) -> None:
    path = tmp_path / "x.sqlite3"
    opened = open_for_migration(path, busy_timeout_ms=100, clock=FixedClock(INSTANT))
    assert isinstance(opened, Success)
    failed = apply_migrations(
        opened.value, script_location=two_revision_script_directory
    )
    assert _code(failed) == WRITE_FAILED
    with opened.value.read_only() as connection:
        report = check_revision(
            connection, script_location=two_revision_script_directory
        )
        assert report.state is RevisionState.BEHIND
        assert "half_table" not in {row.name for row in schema_objects(connection)}
    opened.value.close()


def test_env_module_imports_without_running_a_migration() -> None:
    module = importlib.import_module("crypto_lab.persistence.migrations.env")
    assert callable(module.run_migrations)


@pytest.mark.parametrize("statement", TERMINAL_STATE_CHANGE_STATEMENTS)
def test_every_trigger_and_state_check_fires(
    seeded_database: SqliteDatabase, statement: str
) -> None:
    with seeded_database.connection() as connection:
        with pytest.raises(IntegrityError):
            connection.execute(text(statement))
```

  plus: every table, index and trigger name of §3.3–§3.4 present in
  `sqlite_master`, including `engine_slots`' composite primary key
  `(experiment_id, logical_slot_id)`, the `engine_runs` unique triple and the
  absence of any `(logical_slot_id, attempt_number)` index (reading 7); every
  CHECK of §3.3 refused by a raw `INSERT` of a violating
  row (parametrized over the 15.2 state rows, the run shape rows, the decision
  outcome rows, the owner variants); `downgrade` returns the database to
  `EMPTY` with no user table; `PRAGMA foreign_key_check` empty after upgrade;
  `application_id` set on `EMPTY` and refused when foreign; the `migration-check`
  profile argv row and rejection row in `test_uv_launcher.py`; the verifier
  profile tuple and hash in the Stage 3 guard; `scripts/verify_migrations.py`
  returns `0` on a fresh temporary database (invoked in-process through its
  `main(argv)`).
- [ ] **Step 2: Run the focused set and confirm every new test fails for the
  expected reason** (`ImportError`; the launcher hash pin failing until the
  clause exists; the verifier hash pin failing until the step exists).
- [ ] **Step 3: Minimum GREEN.** The seven modules, the script, the launcher
  clause, the verifier step, the guard edits.
- [ ] **Step 4: Focused GREEN.** `tests\unit\persistence tests\safety tests\unit\test_package_layout.py -q`,
  then the launcher `migration-check` profile itself.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\safety tests\architecture tests\integration`.
**Windows-specific tests.** The refused-open no-mutation hashes on Windows
paths; sidecar files after `close()`.
**Minimum passing evidence.** Focused set green; `migration-check` green;
`verify.ps1` step order pinned.
**Security and boundary review.** No `alembic.ini`; `env.py` reads no
environment and configures no logging; no DDL string interpolates a value; the
script writes only under its temporary directory and removes it; no `experiments`
edit.
**Independent review.** Declared readings 6, 7, 8, 13, 14, 15, 16, 17, 18; the
CHECK expressions against the record validators of §3.1 (matrix A field by
field).
**Commit message.** `feat: add the stage 8 relational schema and alembic migration checks`

### Task 3 — Row codecs, registries, readers, the recorder and the two registry ports

**Objective.** Deliver the lossless codecs for every persisted record and the
insert-only registries: the diagnostic reader and recorder, the availability
observation reader and writer, the strategy-version and dataset repositories
behind their new ports, and the artifact-owner registry; deliver the read-only
consistency report of §4.6 (its first consumers are this task's recorder tests);
prove the round-trip properties of §7.3, C-25 (a), C-29 (c), C-31 and the
Task 3 half of C-32.
**Prerequisites.** Task 2.
**Files created.** `src/crypto_lab/persistence/codecs.py`,
`src/crypto_lab/persistence/registries.py`, `src/crypto_lab/datasets/ports.py`,
`src/crypto_lab/strategy/ports.py`, `tests/property/test_persistence_codecs.py`,
`tests/unit/persistence/test_sqlite_registries.py` (its tests use the
migrated `sqlite_database` and `fixed_clock` fixtures Tasks 1–2 created; no
conftest change),
`tests/unit/datasets/test_dataset_ports.py`,
`tests/unit/strategy/test_strategy_ports.py`.
**Files modified.** `src/crypto_lab/persistence/database.py` (adds
`ConsistencyReport` and `SqliteDatabase.consistency_report()`, §4.6 — the eight
read-only count queries of that section's inventory over the Task 2 schema, no
new import root),
`tests/persistence_support/harness.py` (adds `causal_edges`,
`install_refusing_edge_trigger`, `install_refusing_partition_trigger`,
`sample_strategy_version` and `sample_dataset_with_partitions`, §7.1; the
first three need only `raw_connection` and the Task 2 tables, the two builders
only the committed `strategy` and `datasets` modules),
`src/crypto_lab/datasets/__init__.py` and
`src/crypto_lab/strategy/__init__.py` (sorted exports of the new ports),
`tests/safety/test_stage3_boundaries.py` (paths 103 → 107; `DatasetRepository`
released, deferred 34 → 33), `tests/unit/test_package_layout.py` (→ 107), the
two cross-pin files, `tests/safety/test_stage5_boundaries.py` (the
`registries.py`/`sqlalchemy` pair; `_EXPECTED_READER_IMPLEMENTATIONS` 4 → 5),
`tests/architecture/test_package_import_boundaries.py` (anchors for
`artifacts`, `datasets`, `strategy`).
**Interfaces consumed.** Every record of §3.1, `canonical_json_bytes`,
`format_utc`, `format_decimal`, `ARTIFACT_OWNER_ADAPTER`, `artifact_owner_hash`,
`validate_dataset_identity`, the `*Row` classes, `SqliteDatabase`,
`DiagnosticRecorder`, `DiagnosticReader`, `RuntimeAvailabilityObservationReader`,
`ConfigSnapshot` and `snapshot_configuration` (reading 22), the doubles'
`sample_diagnostic(...)` overrides for `diagnostic_id` and `causal_diagnostic_ids`.
**Interfaces produced.** In `codecs.py`, one pair per record:
`encode_experiment(record) -> ExperimentRowValues` /
`decode_experiment(row) -> Result[ExperimentRecord]` (and `encode_engine_slots`,
`encode_engine_run`/`decode_engine_run`, `encode_command_invocation`/…,
`encode_run_event`/…, `encode_retry_decision`/…, `encode_observation`/…,
`encode_diagnostic`/…, `encode_strategy_version`/…, `encode_dataset`/…,
`encode_dataset_partition`/…, `encode_artifact_owner`/`decode_artifact_owner`),
one `egress_payload_<record>(row) -> Mapping[str, object]` per record (the
JSON-mode payload the decoder validates, exposed so the N1 tests can assert on
it before validation — `egress_payload_command_invocation` is the one the
sketch names),
`utc_to_micros(datetime) -> int`, `micros_to_utc_text(int) -> str`,
`load_snapshot(text) -> object`; in `registries.py`: `SqliteDiagnosticReader`,
`SqliteDiagnosticRecorder` (whose `record` also derives the `diagnostic_causes`
edges of §3.3.9), `SqliteAvailabilityObservationReader`,
`SqliteAvailabilityObservationWriter`, `SqliteConfigurationSnapshotWriter`
(`freeze(experiment_id, snapshot)`, `get(experiment_id)`, §4.4),
`SqliteStrategyVersionRepository`,
`SqliteDatasetRepository`, `SqliteArtifactOwnerRegistry` (§4.4), each
constructed over a `Connection` (transaction-bound) except the recorder, which
takes the `SqliteDatabase`; in `database.py`:
`SqliteDatabase.consistency_report() -> ConsistencyReport` (§4.6: the frozen
dataclass of the eight counts `dangling_diagnostic_references`,
`slot_identity_mismatches`, `spec_projection_mismatches`,
`queued_without_snapshot`, `causal_edge_mismatches`,
`unresolved_causal_references`, `registry_projection_mismatches`,
`foreign_key_violations` — §4.6's list is the inventory, every member computed
by its §4.6 query in a read-only session, none defaulted); in
`tests/persistence_support/harness.py`: `causal_edges`,
`install_refusing_edge_trigger`, `install_refusing_partition_trigger`,
`sample_strategy_version`, `sample_dataset_with_partitions` (§7.1);
in the port modules: `DatasetRepository` and `StrategyVersionRepository`
(reading 12).
**Owned schema/migration/configuration changes.** None (tables exist from
Task 2).
**Guard/dependency transitions.** §2.6: paths → 107; deferred → 33; reader
census → 5; pairs → 10; architecture anchors.

- [ ] **Step 1: Focused RED.**

```python
@given(records=engine_run_records())
@settings(max_examples=120, deadline=None)
def test_engine_run_records_round_trip_losslessly(records: EngineRunRecord) -> None:
    decoded = decode_engine_run(_row(encode_engine_run(records)))
    assert isinstance(decoded, Success)
    assert decoded.value == records
    assert canonical_json_bytes(decoded.value) == canonical_json_bytes(records)


@given(instant=utc_instants())
def test_timestamps_round_trip_to_the_microsecond(instant: datetime) -> None:
    micros = utc_to_micros(instant)
    assert micros_to_utc_text(micros) == format_utc(instant)


def test_a_null_column_is_missing_and_never_null_on_egress() -> None:
    values = encode_command_invocation(sample_invocation(_C.PENDING))
    assert values["deadline_utc"] is None
    payload = egress_payload_command_invocation(_row(values))
    assert "deadline_utc" not in payload
    assert None not in payload.values()


def test_the_recorder_is_idempotent_and_visible_to_the_next_transaction(
    sqlite_database: SqliteDatabase,
) -> None:
    recorder = SqliteDiagnosticRecorder(sqlite_database, clock=FixedClock(INSTANT))
    diagnostic = sample_diagnostic()
    assert isinstance(recorder.record(diagnostic), Success)
    later = diagnostic.model_copy(update={"timestamp_utc": INSTANT + timedelta(1)})
    assert isinstance(recorder.record(later), Success)
    with sqlite_database.read_only() as connection:
        reader = SqliteDiagnosticReader(connection, clock=FixedClock(INSTANT))
        stored = reader.get(diagnostic.diagnostic_id)
        assert isinstance(stored, Success)
        assert stored.value == diagnostic


def test_dataset_registration_is_idempotent_on_identical_content(
    sqlite_database: SqliteDatabase,
) -> None:
    descriptor, partitions = sample_dataset_with_partitions()
    with sqlite_database.connection() as connection:
        repository = SqliteDatasetRepository(connection, clock=FixedClock(INSTANT))
        assert isinstance(repository.register(descriptor, partitions), Success)
        assert isinstance(repository.register(descriptor, partitions), Success)
        listed = repository.list_partitions(descriptor.dataset_id)
        assert isinstance(listed, Success)
        assert listed.value == partitions
        connection.commit()


def test_every_owner_variant_round_trips_and_a_two_variant_row_is_refused(
    sqlite_database: SqliteDatabase,
) -> None: ...


def test_causal_edges_converge_under_the_referrer_first_order(
    sqlite_database: SqliteDatabase,
) -> None:
    recorder = SqliteDiagnosticRecorder(sqlite_database, clock=FixedClock(INSTANT))
    additional = sample_diagnostic(diagnostic_id=f"diag_{UUID_B}")
    primary = sample_diagnostic(causal_diagnostic_ids=(additional.diagnostic_id,))
    assert isinstance(recorder.record(primary), Success)  # the Stage 7 order
    report = sqlite_database.consistency_report()
    assert (report.unresolved_causal_references, report.causal_edge_mismatches) == (
        1,
        0,
    )
    assert causal_edges(sqlite_database) == ()
    assert isinstance(recorder.record(additional), Success)
    edge = (primary.diagnostic_id, additional.diagnostic_id)
    assert causal_edges(sqlite_database) == (edge,)
    report = sqlite_database.consistency_report()
    assert (report.unresolved_causal_references, report.causal_edge_mismatches) == (
        0,
        0,
    )
    assert isinstance(recorder.record(additional), Success)  # replay writes no edge
    assert causal_edges(sqlite_database) == (edge,)


def test_a_refused_edge_rolls_the_diagnostic_back_with_it(
    sqlite_database: SqliteDatabase,
) -> None:
    recorder = SqliteDiagnosticRecorder(sqlite_database, clock=FixedClock(INSTANT))
    cause = sample_diagnostic(diagnostic_id=f"diag_{UUID_B}")
    assert isinstance(recorder.record(cause), Success)
    install_refusing_edge_trigger(sqlite_database)
    referrer = sample_diagnostic(causal_diagnostic_ids=(cause.diagnostic_id,))
    refused = recorder.record(referrer)
    assert isinstance(refused, Failure)
    assert refused.diagnostics[0].error_code == INVARIANT_VIOLATION
    with sqlite_database.read_only() as connection:
        reader = SqliteDiagnosticReader(connection, clock=FixedClock(INSTANT))
        assert isinstance(reader.get(referrer.diagnostic_id), Failure)  # rolled back
        assert isinstance(reader.get(cause.diagnostic_id), Success)
    assert causal_edges(sqlite_database) == ()


def test_a_frozen_snapshot_round_trips_and_a_tampered_byte_is_refused(
    sqlite_database: SqliteDatabase,
) -> None:
    snapshot = snapshot_configuration(ApplicationConfig())
    with sqlite_database.connection() as connection:
        connection.execute(
            insert(ExperimentRow).values(
                **encode_experiment(sample_experiment(_E.DRAFT))
            )
        )
        writer = SqliteConfigurationSnapshotWriter(
            connection, clock=FixedClock(INSTANT)
        )
        before = writer.get(EXPERIMENT_ID)
        assert isinstance(before, Success)
        assert not isinstance(before.value, ConfigSnapshot)  # MISSING until frozen
        assert isinstance(writer.freeze(EXPERIMENT_ID, snapshot), Success)
        assert isinstance(writer.freeze(EXPERIMENT_ID, snapshot), Success)  # idempotent
        stored = writer.get(EXPERIMENT_ID)
        assert isinstance(stored, Success)
        assert stored.value == snapshot
        # A DRAFT row is not guarded by T-EXP-SNAPSHOT-FROZEN, so the raw edit
        # lands; the validator of the rebuilt ConfigSnapshot refuses it on egress.
        connection.execute(
            text(
                "UPDATE experiments SET configuration_audit_hash = :h "
                "WHERE experiment_id = :e"
            ),
            {"h": "0" * 64, "e": EXPERIMENT_ID},
        )
        tampered = writer.get(EXPERIMENT_ID)
        assert isinstance(tampered, Failure)
        assert tampered.diagnostics[0].error_code == INVARIANT_VIOLATION
        connection.rollback()
```

  plus: the property strategies of §7.3 for every record (including the
  causal-edge convergence property over drawn batches and orders, and the
  frozen-snapshot round trip); `test_a_cited_cause_cannot_be_deleted` (C-31: a
  raw `DELETE` of a cited `diagnostics` row raises `IntegrityError`, and
  `EXPECTED_SCHEMA_OBJECTS` pins both `REFERENCES diagnostics (diagnostic_id) ON DELETE RESTRICT`
  clauses of `diagnostic_causes`); the writer's refusal of a missing experiment
  (`does not exist`) and of a `QUEUED` row whose stored snapshot differs from
  the argument (a raw row inserted at `QUEUED` with the snapshot columns filled
  through the writer first); the mutated-row
  refusal property; `get_many` sorted/unique/256/missing rules; `list_for_adapter`
  order and unboundedness over 300 rows; the writer's identical-row no-op and
  divergent-row invariant; strategy-version registration and `get_by_hash`; the
  owner registry's foreign-key refusal (C-26 owner half);
  `test_a_recorded_diagnostic_is_durable_and_unreferenced` (C-25 (a): `record(d)`,
  a fresh read-only session reads `d` back equal, and
  `consistency_report().dangling_diagnostic_references == 0`);
  `consistency_report()` with every count zero on a migrated empty database,
  and `dangling_diagnostic_references == 1` after an `engine_runs` row whose
  `primary_terminal_diagnostic_id` was never recorded is inserted through
  `encode_engine_run` — the row is `sample_run(_R.FAILED, observed=False)`, an
  intentionally unobserved `FAILED` run (lawful: a `FAILED` record needs no
  observation), so its only absent parent is the diagnostic and the count
  isolates exactly that; its `experiments` and `engine_slots` parents are
  inserted first through `encode_experiment`/`encode_engine_slots` (all Task 3
  codecs);
  `test_dataset_registration_rolls_back_to_its_savepoint` (C-29 c:
  `install_refusing_partition_trigger(sqlite_database, 1)` refuses the second
  partition insert; `register` returns `INV`, no `datasets` row is staged, the
  transaction stays usable and `commit()` publishes nothing of it); the port
  member pins for the two new protocols (`members(DatasetRepository) ==
  {"get_by_hash", "list_partitions", "register"}`,
  `members(StrategyVersionRepository) == {"get_by_hash", "register"}`, both
  `runtime_checkable`, module names pinned); the §2.6 guard expectations
  (deferred set failing until exactly `DatasetRepository` is removed; reader
  census naming the new class).
- [ ] **Step 2: Run the focused set and confirm every new test fails for the
  expected reason.**
- [ ] **Step 3: Minimum GREEN.** The four modules, the two `__init__` exports,
  the guard edits.
- [ ] **Step 4: Focused GREEN.** `tests\unit\persistence tests\property\test_persistence_codecs.py tests\unit\datasets tests\unit\strategy tests\safety tests\architecture -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\property tests\safety tests\architecture`.
**Windows-specific tests.** None new.
**Minimum passing evidence.** Focused set green; the property module green
with `deadline=None` where declared.
**Security and boundary review.** `codecs.py` imports no SQLAlchemy; no
persistence module reads `causal_diagnostic_ids` by attribute (the codec
serializes through `model_dump`; the recorder's two edge statements read the
stored JSON column through `json_each`, §3.3.9); the reader has no traversal;
nothing but `SqliteDiagnosticRecorder.record` writes `diagnostic_causes` and
nothing but `SqliteConfigurationSnapshotWriter.freeze` writes the four
snapshot columns — a source scan over `src/crypto_lab/persistence` for the
**mutating** statements `INSERT INTO diagnostic_causes` and
`UPDATE experiments SET configuration_snapshot_…`/`configuration_audit_hash`/
`material_base_configuration_hash`, which must occur only in those two
methods (reads of the columns and of the relation are lawful elsewhere and are
enumerated when they appear: the §4.6 consistency queries in `database.py`,
this task, and the §4.3.1 step d′ pre-read in `repositories.py`, Task 4, whose
boundary review repeats this scan); every helper and fixture this task's tests
use exists at this boundary (`sqlite_database`, `fixed_clock`, `raw_connection`,
`ok`/`code`, the three Task 3 helpers of §7.1, `consistency_report()`), and no
Task 3 test imports `fixtures.py`, `SqliteHarness` or a lifecycle repository;
no `AttemptToken`
annotation; `datasets/ports.py` and `strategy/ports.py` import only `domain` and
their own package's models.
**Independent review.** Declared readings 4, 10, 11, 12, 22, 23; §3.2 rules E1–E8 and
N1–N5 against the field tables of §3.1; the `MISSING`-count check per record
(2, 5, 11, 5, 0, 1, 4, owner variants 1/2/2); the edge statements of §3.3.9
against the C-31 sequence by hand; the `ConfigSnapshot` egress path through the
record's own validator.
**Commit message.** `feat: add the sqlite unit of work row codecs and base registries`

### Task 4 — The unit of work, the lifecycle repositories and the re-pointed contract suite

**Objective.** Deliver `SqliteUnitOfWork`/`SqliteTransaction` and the four
lifecycle repositories over the codecs, build the SQLite test-support package,
and re-point the Stage 5 port contract suite at SQLite with the disposition of
§7.2; prove C-1–C-4, C-9, C-14, C-26 and the repository half of C-27.
**Prerequisites.** Task 3.
**Files created.** `src/crypto_lab/persistence/unit_of_work.py`,
`src/crypto_lab/persistence/repositories.py`,
`tests/persistence_support/fixtures.py` (the §7.1.1 fence, verbatim),
`tests/unit/persistence/test_sqlite_unit_of_work.py`,
`tests/unit/persistence/test_sqlite_repositories.py`,
`tests/unit/persistence/test_sqlite_run_events.py`.
**Files modified.** `tests/persistence_support/harness.py` (adds
`SqliteHarness`, `put_lifecycle_parents`, the remaining promoted helpers,
`sql_identity_literal`, `install_refusing_slot_trigger`,
`install_ignoring_update_trigger` and `CasSubject`/`CAS_SUBJECTS`; §7.1),
`tests/unit/experiments/test_port_contracts.py` (§7.2: the
`"sqlite"` parameter, the `harness_factory` rewrite, the split, the rename, the
per-case `put_lifecycle_parents` seeding, the one reordering in
`test_latest_attempt…`, the two new event cases, and the three body edits of
`test_a_failed_second_write…` — the `OTHER_EXPERIMENT_ID` seeding line, the
`stored_run` experiment, the final assertions), `tests/unit/persistence/conftest.py`
(the `sqlite_harness` fixture added beside Task 1's and Task 2's), `tests/unit/persistence/test_sqlite_constraints.py` (the
repository half of C-26/C-27), `tests/safety/test_stage3_boundaries.py` (→ 109),
`tests/unit/test_package_layout.py` (→ 109), the two cross-pin files,
`tests/safety/test_stage5_boundaries.py` (two pairs → 12),
`tests/architecture/test_package_import_boundaries.py` (anchors for
`experiments`, `adapters`).
**Interfaces consumed.** The codecs and registries of Task 3 (including
`SqliteConfigurationSnapshotWriter`), `SqliteDatabase` and its Task 3
`consistency_report()`, the Task 3 helpers `causal_edges`,
`install_refusing_edge_trigger` and `install_refusing_partition_trigger`,
the six port protocols, `RetryDecisionInsertOutcome`, `PortHarness`, the
doubles' `sample_*` builders and `FixedClock`; for the queue-edge guard of
§4.3.1 step d′: `experiment_configuration_hash`, `retry_policy_from_config`,
`ApplicationConfig.model_validate_json`; for the harness helpers of §7.1:
`build_experiment_spec`, `snapshot_configuration`,
`material_base_configuration_hash`, `SelectedEngineSlot`,
`sample_slot_compatibility`.
**Interfaces produced.** `SqliteUnitOfWork(database, clock)` (keeps a weak set
of its open transactions, exposed as `open_transactions()` for the harness's
teardown rollback), `SqliteTransaction` (§4.2; extra members
`availability_observation_writer`, `configuration_snapshots`, `artifact_owners`,
`strategy_versions`, `datasets`), `SqliteExperimentRepository`,
`SqliteEngineRunRepository`, `SqliteCommandInvocationRepository`,
`SqliteRetryDecisionRepository` (§4.3); the Task 4 test-support helpers of §7.1
(`consistency_report()` is Task 3's and is only consumed here).
**Owned schema/migration/configuration changes.** None.
**Guard/dependency transitions.** §2.6: paths → 109; pairs → 12; anchors.

- [ ] **Step 1: Focused RED.**

```python
def test_a_refused_write_leaves_the_transaction_usable(
    sqlite_harness: SqliteHarness,
) -> None:
    stored = sample_experiment(_E.DRAFT)
    _put_experiment(sqlite_harness, stored)
    loser = sqlite_harness.unit_of_work().begin()
    assert _ok(loser.experiments.get(EXPERIMENT_ID)) == stored
    winner = sqlite_harness.unit_of_work().begin()
    _ok(winner.experiments.compare_and_swap(stored.revision, _bump(stored)))
    _commit(winner)
    refused = loser.experiments.compare_and_swap(stored.revision, _bump(stored))
    assert _code(refused) == CONCURRENCY_CONFLICT
    # The statement was aborted, not the transaction: reads still answer from
    # the snapshot and a commit publishes nothing.
    assert _ok(loser.experiments.get(EXPERIMENT_ID)) == stored
    _commit(loser)
    assert sqlite_harness.committed_experiments() == (_bump(stored),)


def test_concurrent_creation_of_one_identity_refuses_the_later_writer(
    sqlite_harness: SqliteHarness,
) -> None:
    first = sqlite_harness.unit_of_work().begin()
    second = sqlite_harness.unit_of_work().begin()
    _ok(first.experiments.add(sample_experiment(_E.DRAFT)))
    _commit(first)
    lost = second.experiments.add(sample_experiment(_E.VALIDATED))
    assert _code(lost) == CONCURRENCY_CONFLICT
    _commit(second)
    assert sqlite_harness.committed_experiments() == (sample_experiment(_E.DRAFT),)


def _with_spec(record: ExperimentRecord, spec: ExperimentSpec) -> ExperimentRecord:
    # A changed spec carries its recomputed identity through the canonical helper.
    return record.model_copy(
        update={"spec": spec, "spec_hash": experiment_spec_hash(spec)}
    )


def test_the_slot_projection_agrees_with_the_spec_after_every_write(
    sqlite_harness: SqliteHarness,
) -> None:
    experiment = sample_experiment(_E.DRAFT)
    _put_experiment(sqlite_harness, experiment)
    assert slot_rows(sqlite_harness) == expected_slot_rows(experiment)
    # other_slots_spec() changes the slot set (§7.1), so an untouched projection
    # would be visibly wrong; the DRAFT record carries no slot_compatibility.
    replaced = _bump(_with_spec(experiment, other_slots_spec()))
    transaction = sqlite_harness.unit_of_work().begin()
    _ok(transaction.experiments.compare_and_swap(experiment.revision, replaced))
    _commit(transaction)
    assert slot_rows(sqlite_harness) == expected_slot_rows(replaced)


def test_a_frozen_spec_cannot_change_after_queued(
    sqlite_harness: SqliteHarness,
) -> None:
    queued = sample_experiment(_E.QUEUED)
    _put_experiment(sqlite_harness, queued)
    transaction = sqlite_harness.unit_of_work().begin()
    # other_spec() changes a non-slot field (§7.1), so the QUEUED record's
    # slot_compatibility still validates and the repository guard is reached.
    refused = transaction.experiments.compare_and_swap(
        queued.revision, _bump(_with_spec(queued, other_spec()))
    )
    assert _code(refused) == INVARIANT_VIOLATION
    transaction.rollback()
    assert sqlite_harness.committed_experiments() == (queued,)


def test_slot_identity_is_scoped_by_its_experiment(
    sqlite_harness: SqliteHarness,
) -> None:
    first = sample_experiment(_E.QUEUED)
    second = three_slot_experiment(_E.QUEUED, experiment_id=OTHER_EXPERIMENT_ID)
    _put_experiment(sqlite_harness, first)
    _put_experiment(
        sqlite_harness, second
    )  # A: SLOT_A/SLOT_B twice, SLOT_C (gamma pair) once
    # E₁'s first attempt is terminal, so in B only the three-field UNIQUE can
    # refuse the duplicate (the active-attempt partial index admits a new row).
    _put_run(sqlite_harness, sample_run(_R.FAILED, observed=False))
    _put_run(
        sqlite_harness,
        sample_run(_R.PENDING, run_id=OTHER_RUN_ID, experiment_id=OTHER_EXPERIMENT_ID),
    )  # A: same slot and attempt number under another experiment
    transaction = sqlite_harness.unit_of_work().begin()
    duplicate = transaction.engine_runs.add_attempt(
        sample_run(_R.PENDING, run_id=f"run_{UUID_C}")
    )
    assert _code(duplicate) == CONCURRENCY_CONFLICT  # B: full three-field identity
    # SLOT_C exists only under OTHER_EXPERIMENT_ID (three_slot_draft, §7.1.1); the
    # run is shape-valid — its adapter and engine are the slot row's — so only the
    # composite foreign key (experiment half mismatched) can refuse it.
    foreign_slot = transaction.engine_runs.add_attempt(
        sample_run(
            _R.PENDING,
            run_id=f"run_{UUID_D}",
            logical_slot_id=SLOT_C,
            adapter=ADAPTER_GAMMA,
            engine=ENGINE_GAMMA,
        )
    )
    assert _code(foreign_slot) == INVARIANT_VIOLATION  # C: composite foreign key
    control = transaction.engine_runs.add_attempt(
        sample_run(
            _R.PENDING,
            run_id=f"run_{UUID_D}",
            experiment_id=OTHER_EXPERIMENT_ID,
            logical_slot_id=SLOT_C,
            adapter=ADAPTER_GAMMA,
            engine=ENGINE_GAMMA,
        )
    )
    assert isinstance(control, Success)  # C: the same slot under its own experiment
    transaction.rollback()
    assert len(sqlite_harness.committed_engine_runs()) == 2


@pytest.mark.parametrize("subject", CAS_SUBJECTS, ids=lambda s: s.name)
def test_compare_and_swap_refuses_missing_then_stale_then_step_in_order(
    sqlite_harness: SqliteHarness, subject: CasSubject
) -> None:
    subject.seed_parents(sqlite_harness)
    stored = subject.record()
    subject.put(sqlite_harness, stored)
    transaction = sqlite_harness.unit_of_work().begin()
    repository = getattr(transaction, subject.member)
    absent = subject.rekey(stored)
    # missing + wrong step -> conflict: step b decides before step d
    assert (
        _code(repository.compare_and_swap(0, subject.bump(absent)))
        == CONCURRENCY_CONFLICT
    )
    # stale + wrong step -> conflict: step c decides before step d
    stale = repository.compare_and_swap(stored.revision + 5, subject.bump(stored))
    assert _code(stale) == CONCURRENCY_CONFLICT
    # matching + wrong step -> invariant, nothing written
    skipped = subject.bump(subject.bump(stored))
    assert (
        _code(repository.compare_and_swap(stored.revision, skipped))
        == INVARIANT_VIOLATION
    )
    assert _ok(repository.get(subject.identity(stored))) == stored
    # matching + valid step -> provisional success: this transaction sees it,
    # a fresh reader does not until commit
    swapped = _ok(repository.compare_and_swap(stored.revision, subject.bump(stored)))
    assert swapped == subject.bump(stored)
    assert _ok(repository.get(subject.identity(stored))) == swapped
    fresh = sqlite_harness.unit_of_work().begin()
    assert _ok(getattr(fresh, subject.member).get(subject.identity(stored))) == stored
    fresh.rollback()
    transaction.rollback()
    assert subject.committed(sqlite_harness) == (stored,)


@pytest.mark.parametrize("subject", CAS_SUBJECTS, ids=lambda s: s.name)
def test_compare_and_swap_observes_this_transactions_earlier_writes(
    sqlite_harness: SqliteHarness, subject: CasSubject
) -> None:
    subject.seed_parents(sqlite_harness)
    record = subject.record()
    transaction = sqlite_harness.unit_of_work().begin()
    repository = getattr(transaction, subject.member)
    _ok(subject.insert(repository, record))  # uncommitted; visible to the pre-read
    first = _ok(repository.compare_and_swap(record.revision, subject.bump(record)))
    # The pre-read now sees this transaction's own swap: the same expected
    # revision is stale (step c), and nothing is written.
    again = repository.compare_and_swap(record.revision, subject.bump(record))
    assert _code(again) == CONCURRENCY_CONFLICT
    second = _ok(repository.compare_and_swap(first.revision, subject.bump(first)))
    assert _ok(repository.get(subject.identity(record))) == second
    transaction.rollback()
    assert subject.committed(sqlite_harness) == ()


def test_a_zero_row_conditional_update_is_a_conflict_after_the_checks(
    sqlite_harness: SqliteHarness,
) -> None:
    put_lifecycle_parents(sqlite_harness, run=True)
    stored_run = sample_run(_R.PENDING)
    install_ignoring_update_trigger(
        sqlite_harness.database, "engine_runs", "run_id", RUN_ID
    )
    transaction = sqlite_harness.unit_of_work().begin()
    refused = transaction.engine_runs.compare_and_swap(
        stored_run.revision, _bump_run(stored_run, _R.VALIDATING)
    )
    # Steps a-d passed (row present, revision matches, step valid); the UPDATE
    # touched no row, which is step f's conflict, not an invariant.
    assert _code(refused) == CONCURRENCY_CONFLICT
    assert _ok(transaction.engine_runs.get(RUN_ID)) == stored_run
    _commit(transaction)
    assert sqlite_harness.committed_engine_runs() == (stored_run,)


def test_queueing_requires_a_frozen_snapshot_that_agrees_with_the_spec(
    sqlite_harness: SqliteHarness,
) -> None:
    config = ApplicationConfig()
    validated = _with_spec(sample_experiment(_E.VALIDATED), config_backed_spec(config))
    _put_experiment(sqlite_harness, validated)
    queued = _with_spec(
        sample_experiment(_E.QUEUED, revision=validated.revision + 1),
        config_backed_spec(config),
    )
    transaction = sqlite_harness.unit_of_work().begin()
    unfrozen = transaction.experiments.compare_and_swap(validated.revision, queued)
    assert _code(unfrozen) == INVARIANT_VIOLATION  # step d': no frozen snapshot
    assert _ok(transaction.experiments.get(EXPERIMENT_ID)) == validated
    snapshots = transaction.configuration_snapshots
    _ok(snapshots.freeze(EXPERIMENT_ID, snapshot_configuration(other_config())))
    disagreeing = transaction.experiments.compare_and_swap(validated.revision, queued)
    assert _code(disagreeing) == INVARIANT_VIOLATION  # step d': hash and policy differ
    _ok(
        snapshots.freeze(EXPERIMENT_ID, snapshot_configuration(config))
    )  # pre-QUEUED replace
    assert (
        _ok(transaction.experiments.compare_and_swap(validated.revision, queued))
        == queued
    )
    _commit(transaction)
    later = sqlite_harness.unit_of_work().begin()
    assert _ok(
        later.configuration_snapshots.get(EXPERIMENT_ID)
    ) == snapshot_configuration(config)
    refrozen = later.configuration_snapshots.freeze(
        EXPERIMENT_ID, snapshot_configuration(other_config())
    )
    assert _code(refrozen) == INVARIANT_VIOLATION  # frozen at QUEUED
    later.rollback()
    assert sqlite_harness.committed_experiments() == (queued,)


def test_a_multi_statement_method_rolls_back_to_its_savepoint(
    sqlite_harness: SqliteHarness,
) -> None:
    install_refusing_slot_trigger(sqlite_harness.database, SLOT_B)
    transaction = sqlite_harness.unit_of_work().begin()
    refused = transaction.experiments.add(sample_experiment(_E.DRAFT))
    assert _code(refused) == INVARIANT_VIOLATION
    # The experiment row inserted before the refused slot is gone with it.
    assert _code(transaction.experiments.get(EXPERIMENT_ID)) == INVARIANT_VIOLATION
    _commit(transaction)
    assert sqlite_harness.committed_experiments() == ()
    assert slot_rows(sqlite_harness) == ()


def test_a_concurrent_identical_append_loses_as_a_conflict(
    sqlite_harness: SqliteHarness,
) -> None:
    put_lifecycle_parents(sqlite_harness, run=True, invocation=True)
    event = sample_run_event(sequence=1)
    first = sqlite_harness.unit_of_work().begin()
    second = sqlite_harness.unit_of_work().begin()
    assert _ok(second.engine_runs.list_events(event.invocation_id)) == ()
    _ok(first.engine_runs.append_event(event))
    _commit(first)
    assert _code(second.engine_runs.append_event(event)) == CONCURRENCY_CONFLICT
    second.rollback()
    third = sqlite_harness.unit_of_work().begin()
    assert _ok(third.engine_runs.append_event(event)) == event
    third.rollback()
```

  plus: every §4.3 row's failure condition (`get` of a missing identity →
  invariant with `does not exist`; every compare-and-swap in the §4.3.1 order —
  no row → conflict, stored revision ≠ expected → conflict, wrong step at the
  matching revision → invariant with nothing written, zero rows or a refused
  promotion at the `UPDATE` → conflict — proven per repository by C-30's three
  tests above and by the retained contract assertions on the `"sqlite"` kind;
  every foreign-key and CHECK refusal → invariant), the C-29 (b) half (a
  refused slot reinsert during a pre-`QUEUED` spec change leaves the stored
  experiment and its slots unchanged), C-2, C-3, C-9, C-14's
  conflicting-content and reused-`event_id` cases, `count_attempts`/
  `latest_attempt`/`get_by_attempt_number` including staged rows within the
  transaction, `list_for_run` order over permuted insertion, the terminal-run
  trigger through the repository (`INV`), the Task 3 `consistency_report()`
  consumed for the counts the repositories govern: `slot_identity_mismatches`
  and `spec_projection_mismatches` zero after every repository write of this
  task's tests, and `queued_without_snapshot == 1` after `put_lifecycle_parents`
  (the scaffolding row of §7.1, the count's only legitimate source); `begin()` twice raises
  `RuntimeError`; root member access raises; `rollback()` twice is a no-op; an
  abandoned transaction is rolled back by `SqliteHarness.close()` and, in the
  pool-reclaim probe, released after `gc.collect()` (§2.8); the §7.2 disposition
  applied and every parametrized case green on both kinds; `sample_run_event`
  is added to `tests/persistence_support/harness.py` if the doubles offer no
  event builder.
- [ ] **Step 2: Run the focused set and confirm every new test fails for the
  expected reason** (`ImportError`; the `"sqlite"` parameter absent).
- [ ] **Step 3: Minimum GREEN.** The two modules, the support package, the
  contract-suite edits, the guard edits.
- [ ] **Step 4: Focused GREEN.** `tests\unit\persistence tests\unit\experiments\test_port_contracts.py tests\safety tests\architecture -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\property tests\safety tests\architecture tests\integration`.
**Windows-specific tests.** Connection and engine disposal in every fixture
(`tmp_path` cleanup on Windows).
**Minimum passing evidence.** The focused set green on both harness kinds; the
moved in-memory halves green unchanged.
**Security and boundary review.** No repository reads the clock except to stamp
its own failures; no SQL from row values (the test trigger installers embed
only `sql_identity_literal` of a fixture constant, §7.1); `tests/doubles/*`
unedited; the `PortHarness` protocol unchanged; `UnitOfWork` member set
unchanged; Task 3's mutating-statement scan repeated over the whole package
with the two lawful read sites named — the §4.3.1 step d′ pre-read of the four
snapshot columns in `repositories.py` (this task) and the §4.6 consistency
queries over the snapshot columns and `diagnostic_causes` in `database.py`
(Task 3) — and no other
occurrence of an `INSERT INTO diagnostic_causes` or an `UPDATE` of a snapshot
column; `tests/persistence_support/fixtures.py` byte-identical to the §7.1.1
fence.
**Independent review.** Declared readings 2, 3, 5, 13, 22; §4.2 step table against
the implementation; §4.3.1 step by step against each of the three
`compare_and_swap` methods (the pre-read precedes every refusal, the savepoint is
entered at step e only, no statement follows a refusal) and against the four
retained contract assertions named there; the §7.2 disposition row by row.
**Commit message.** `feat: add sqlite lifecycle repositories and re-point the port contracts`

### Task 5 — The reconciliation source and the Stage 7 lifecycle over SQLite

**Objective.** Implement `ReconciliationSource` over the tables and prove the
Stage 7 lifecycle and reconciliation behaviour over a real database: the
recorder-before-swap order, the coupled pairs, the enrichment, the external
winner, and every restart row after a close-and-reopen (C-23).
**Prerequisites.** Task 4.
**Files created.** `src/crypto_lab/persistence/reconciliation_source.py`,
`tests/unit/persistence/test_sqlite_reconciliation_source.py`,
`tests/unit/persistence/test_sqlite_supervision_lifecycle.py`,
`tests/integration/persistence/conftest.py`,
`tests/integration/persistence/test_sqlite_restart_reconciliation.py`.
**Files modified.** `tests/safety/test_stage3_boundaries.py` (→ 110),
`tests/unit/test_package_layout.py` (→ 110), the two cross-pin files,
`tests/safety/test_stage5_boundaries.py` (the last pair → 13),
`tests/architecture/test_package_import_boundaries.py` (the
`process_supervision` anchor).
**Interfaces consumed.** `ReconciliationSource`, `RunReconciliationFacts`,
`reconcile_invocations`, `Stage5InvocationLifecycle`, the scripted controller
and doubles of `tests/doubles/supervision.py` (read for their seeding shapes,
not edited), `SqliteUnitOfWork`, `SqliteDiagnosticRecorder`.
**Interfaces produced.** `SqliteReconciliationSource(database, clock)` (§4.5).
**Owned schema/migration/configuration changes.** None.
**Guard/dependency transitions.** §2.6: paths → 110; pairs → 13; anchor.

- [ ] **Step 1: Focused RED.**

```python
def test_listing_returns_exactly_the_nonterminal_and_incomplete_cleanup_rows(
    sqlite_harness: SqliteHarness,
) -> None:
    for record in RECONCILIATION_SEED:
        _put_invocation(sqlite_harness, record)
    source = SqliteReconciliationSource(sqlite_harness.database, FixedClock(INSTANT))
    listed = source.list_reconciliation_targets()
    assert isinstance(listed, Success)
    assert [record.invocation_id for record in listed.value] == EXPECTED_TARGET_ORDER
    assert all(
        record.state not in TERMINAL_COMMAND_INVOCATION_STATES
        or not record.cleanup_complete
        for record in listed.value
    )


def test_run_facts_for_a_missing_run_or_experiment_is_an_invariant(
    sqlite_harness: SqliteHarness,
) -> None:
    source = SqliteReconciliationSource(sqlite_harness.database, FixedClock(INSTANT))
    assert _code(source.run_facts(RUN_ID)) == INVARIANT_VIOLATION


def test_the_source_issues_no_write(sqlite_harness: SqliteHarness) -> None:
    before = total_changes(sqlite_harness.database)
    SqliteReconciliationSource(
        sqlite_harness.database, FixedClock(INSTANT)
    ).list_reconciliation_targets()
    assert total_changes(sqlite_harness.database) == before


def test_a_core_won_terminal_records_the_primary_before_the_coupled_swap(
    sqlite_lifecycle: LifecycleFixture,
) -> None:
    outcome = sqlite_lifecycle.lifecycle.record_terminal(
        sqlite_lifecycle.invocation_id,
        expected_revision=sqlite_lifecycle.invocation_revision,
        target_state=_C.TIMED_OUT,
        primary=sqlite_lifecycle.primary,
        additional=(),
        native_exit_value=MISSING,
    )
    assert isinstance(outcome, Success)
    assert sqlite_lifecycle.recorded_ids() == [sqlite_lifecycle.primary.diagnostic_id]
    assert sqlite_lifecycle.run_state() is _R.TIMED_OUT


@pytest.mark.parametrize("row", RESTART_ROWS, ids=[row.name for row in RESTART_ROWS])
def test_every_reconciliation_row_over_a_reopened_database(
    tmp_path: Path, row: RestartRow
) -> None:
    first = open_test_database(tmp_path, clock=FixedClock(INSTANT))
    try:
        row.seed(first)
    finally:
        first.close()
    reopened = open_test_database(tmp_path, clock=FixedClock(row.now))
    try:
        report = reconcile_invocations(
            source=SqliteReconciliationSource(reopened, FixedClock(row.now)),
            lifecycle=sqlite_lifecycle_over(reopened, row.now),
            controller=row.controller,
            preflight=row.preflight,
            clock=FixedClock(row.now),
            supervisor_instance_id=SUPERVISOR_INSTANCE_ID,
            observer=MISSING,
        )
        assert row.expected_decision(report)
        assert row.expected_state(reopened)
        assert not row.reached_exited_or_success(reopened)
    finally:
        reopened.close()
```

  plus: the twelve named lifecycle scenarios of §7.4 over SQLite (recorder
  failure stops the write; the two `append_event` cases; linked launch and
  start; same-state replay; external winner alone and coupled; lost-swap paths);
  `test_a_recorded_diagnostic_survives_a_refused_swap` (C-25 (b): `record(d)`
  through `SqliteDiagnosticRecorder`, then a `record_terminal` whose CAS is
  refused by a stale expected revision — the terminal write never happens, `d`
  stays readable, the invocation is unchanged and
  `consistency_report().dangling_diagnostic_references` stays 0);
  ordering ties broken by `invocation_id`; a row failing egress named in the
  `INV`; the `(state, deadline_utc)` and listing indexes used (`EXPLAIN QUERY
  PLAN` names the index); every count of `consistency_report()` other than
  `queued_without_snapshot` zero after every scenario (the seeded `QUEUED`
  parents of §7.1 carry no snapshot; §4.6), `causal_edge_mismatches` and
  `unresolved_causal_references` included — the coupled terminal records a
  primary before its additionals and the relation converges (reading 23).
- [ ] **Step 2: Run the focused set and confirm every new test fails for the
  expected reason.**
- [ ] **Step 3: Minimum GREEN.** The module and the guard edits.
- [ ] **Step 4: Focused GREEN.** `tests\unit\persistence tests\integration\persistence tests\safety tests\architecture -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\integration tests\safety tests\architecture tests\contract`.
**Windows-specific tests.** The close-and-reopen across every restart row.
**Minimum passing evidence.** Every restart row green; the lifecycle subset
green; no `EXITED` or success state produced anywhere.
**Security and boundary review.** `process_supervision` never imports
`persistence` (the direction is persistence → `process_supervision.ports`);
the source issues no write; no `experiments` or `process_supervision` module
edited (file counts 11 and 12 unchanged).
**Independent review.** Declared readings 3, 4; §1.5 notes 3–5; the restart
rows against the Stage 7 plan section 8.5 decisions.
**Commit message.** `feat: add the sqlite reconciliation source and drive the lifecycle over sqlite`

### Task 6 — Driver races, retry-decision recovery, interrupted writers and Windows locking

**Objective.** Prove the remaining rows of §5.1 through the existing drivers:
C-5–C-8, C-10–C-13, C-17, C-18, C-24; add the twelfth `subprocess` importer.
**Prerequisites.** Task 5.
**Files created.** `tests/unit/persistence/test_sqlite_driver_races.py`,
`tests/unit/persistence/test_sqlite_retry_decisions.py`,
`tests/integration/persistence/test_wal_restart.py`.
**Files modified.** `tests/unit/persistence/test_sqlite_database.py` (C-18),
`tests/persistence_support/harness.py` (adds `InterleavingUnitOfWork` and
`CountingUnitOfWork`, §7.1), `tests/safety/test_stage6_boundaries.py`
(`_SUBPROCESS_IMPORTERS` → 12), `tests/safety/test_stage7_boundaries.py`
(`len == 12`, the retired "eleven" phrase), `docs/development/verification.md`
(the "twelve `subprocess` importers" sentence).
**Interfaces consumed.** `run_operation`, `transition_experiment`,
`begin_linked_launch`, `transition_run`, `cancel_experiment`,
`create_successor`, `evaluate_retry`, `aggregate_experiment`, the request types,
`FixedClock`, `SequentialIdentitySource`, `InterleavingUnitOfWork`.
**Interfaces produced.** None in `src`; the support helpers.
**Owned schema/migration/configuration changes.** None.
**Guard/dependency transitions.** §2.6: subprocess importers 11 → 12 and the
guide sentence.

- [ ] **Step 1: Focused RED.**

```python
def test_run_operation_reloads_once_after_a_lost_experiment_swap(
    sqlite_harness: SqliteHarness,
) -> None:
    stored = sample_experiment(_E.DRAFT)
    _put_experiment(sqlite_harness, stored)

    def winner_commits() -> None:
        transaction = sqlite_harness.unit_of_work().begin()
        _ok(transaction.experiments.compare_and_swap(0, _bump(stored)))
        _commit(transaction)

    interleaving = InterleavingUnitOfWork(
        sqlite_harness.unit_of_work(), after_read=winner_commits
    )
    outcome = transition_experiment(
        ExperimentTransitionRequest(
            schema_version="1.0.0",
            experiment_id=EXPERIMENT_ID,
            expected_revision=0,
            target_state=_E.VALIDATED,
            reason_code="TEST.TRANSITION",
        ),
        unit_of_work=interleaving,
        clock=FixedClock(INSTANT),
    )
    assert _code(outcome) == CONCURRENCY_CONFLICT
    assert interleaving.begins == 2
    assert sqlite_harness.committed_experiments() == (_bump(stored),)


def test_a_divergent_concurrent_decision_replays_the_durable_winner(
    retry_fixture: RetryFixture,
) -> None:
    # The winner is committed by the hook after this evaluation's phase-1 read
    # saw the key absent; the evaluation's own candidate diverges because the
    # observation expired in between (the clock advanced before the run).
    retry_fixture.clock.advance(retry_fixture.observation_ttl_seconds + 1)
    interleaving = retry_fixture.interleaving_unit_of_work(
        after_read=retry_fixture.commit_fresh_winner_from_another_connection
    )
    outcome = evaluate_retry(
        retry_fixture.request, unit_of_work=interleaving, clock=retry_fixture.clock
    )
    assert isinstance(outcome, Success)
    winner = retry_fixture.winner()
    assert outcome.value == winner
    assert interleaving.begins == 2
    assert retry_fixture.harness.committed_retry_decisions() == (winner,)
    assert retry_decision_semantic_projection(
        winner
    ) != retry_decision_semantic_projection(retry_fixture.divergent_candidate())


def test_a_durable_retry_delay_is_reused_after_reopen(tmp_path: Path) -> None:
    fixture = RetryFixture.seeded_allowed(tmp_path, delay_seconds=120)
    fixture.close()
    reopened = RetryFixture.reopen(tmp_path)
    early = create_successor(
        reopened.request,
        unit_of_work=reopened.unit_of_work(),
        clock=reopened.clock,
        identity_source=reopened.identity_source,
    )
    assert _code(early) == RETRY_NOT_BEFORE_NOT_REACHED
    reopened.clock.advance(120)
    created = create_successor(
        reopened.request,
        unit_of_work=reopened.unit_of_work(),
        clock=reopened.clock,
        identity_source=reopened.identity_source,
    )
    assert isinstance(created, Success)
    assert created.value.attempt.attempt_number == 2
    reopened.close()


def test_an_interrupted_writer_leaves_no_partial_row_after_reopen(
    tmp_path: Path,
) -> None:
    database = open_test_database(tmp_path, clock=FixedClock(INSTANT))
    _put_experiment(SqliteHarness(database), sample_experiment(_E.DRAFT))
    database.close()
    child = subprocess.Popen(  # noqa: S603 - reviewed list argv, no shell
        [sys.executable, "-I", "-B", "-c", HOLDING_WRITER_PROGRAM, str(database.path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        shell=False,
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == b"HELD"
        blocked = open_test_database(tmp_path, clock=FixedClock(INSTANT))
        try:
            transaction = SqliteUnitOfWork(blocked, FixedClock(INSTANT)).begin()
            assert (
                _code(transaction.experiments.add(sample_experiment(_E.VALIDATED)))
                == CONCURRENCY_CONFLICT
            )
            transaction.rollback()
        finally:
            blocked.close()
    finally:
        child.kill()
        child.wait(timeout=30)
    reopened = open_test_database(tmp_path, clock=FixedClock(INSTANT))
    try:
        assert SqliteHarness(reopened).committed_experiments() == (
            sample_experiment(_E.DRAFT),
        )
        with reopened.read_only() as connection:
            names = {row.name for row in schema_objects(connection)}
            assert "crash_probe" not in names
            assert check_revision(connection).state is RevisionState.CURRENT
        assert reopened.consistency_report().foreign_key_violations == 0
    finally:
        reopened.close()
```

  where `HOLDING_WRITER_PROGRAM` is one line: open the path with `sqlite3`,
  `isolation_level=None`, execute `BEGIN IMMEDIATE`, `CREATE TABLE crash_probe
  (x INTEGER)` and `INSERT INTO crash_probe VALUES (1)` (a throwaway table, so
  no record CHECK is involved and the uncommitted DDL is the partial write the
  reopen must not see), print `HELD`, flush, block on `sys.stdin.readline()`.
  Plus: C-6, C-8, C-10 (both orders), C-11 (both orders), C-12, C-13 (one and
  two interleavings through `on_attempts=(1,)` and `(1, 2)` with `begins`
  pinned), C-18; every driver race names the exact code of §5.1 (`CONF` or
  `CORE.INVARIANT_VIOLATION`) rather than "a failure"; `busy_timeout_ms=100`
  in every fixture; the subprocess-importer guard expecting twelve.
- [ ] **Step 2: Run the focused set and confirm every new test fails for the
  expected reason** (the interleaving helper absent; the importer count at
  eleven).
- [ ] **Step 3: Minimum GREEN.** The helpers, the tests, the guard edits, the
  guide sentence.
- [ ] **Step 4: Focused GREEN.** `tests\unit\persistence tests\integration\persistence tests\safety -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\integration tests\safety tests\contract`.
**Windows-specific tests.** C-17 (cross-process lock and interrupted writer),
C-18 (read-only attribute), sidecar tolerance.
**Minimum passing evidence.** Every §5.1 row green; the child terminated and
awaited in `finally:` with no survivor.
**Security and boundary review.** One `subprocess` importer added, list argv,
`shell=False`, the venv interpreter, single-line `-c` program; no sleep-based
synchronization; every connection closed in `finally:`.
**Independent review.** Declared readings 3 and 19; §1.4 row 9 (the measured
residual) and row 6 (the unreachable divergent-loser branch); §1.5 notes 1–2
resolved as documented behaviour by C-7 and C-8, note 12 closed by C-12.
**Commit message.** `test: prove sqlite concurrency, retry recovery and interrupted writers`

### Task 7 — Composition: the existing operations over the durable repositories

**Objective.** Compose the Stage 5 in-memory flow and a supervised fake-adapter
run over `SqliteUnitOfWork`, `SqliteDiagnosticRecorder`,
`SqliteReconciliationSource`, the registries and the owner registry, with
restart reconciliation over the real database; assert zero dangling references,
zero open transactions during child execution, and no success state or
`RunManifest`. This is the implementation commit whose hash the roadmap records.
**Prerequisites.** Task 6.
**Files created.** `tests/persistence_support/supervised.py`
(`SupervisedSqliteFlow`, the composition of §7.1.2),
`tests/integration/persistence/test_stage8_durable_flow.py`,
`tests/integration/persistence/test_stage8_supervised_flow.py`.
**Files modified.** None in `src`; `tests/persistence_support/harness.py`
(adds `DurableFlow`, the two-slot composition of §7.1.1's flow).
**Interfaces consumed.** Every Stage 5 operation, `apply_command_semantic_outcome`,
`ApplicationConfig`, `snapshot_configuration`, `material_base_configuration_hash`,
`retry_policy_from_config` (the queue freeze of reading 22 exercised end to
end: `ExperimentCreationRequest` carries the flow's draft and
`material_base_configuration_hash(config)`, and `ExperimentQueueRequest`
carries the same hash and `retry_policy_from_config(config.scheduler.retry)`,
which are exactly the values the frozen `snapshot_configuration(config)`
yields), the §7.1.1 constructors `retrying_config`, `config_backed_draft`,
`supervised_draft`, `RetryDecisionOutcome`, `RetryDenialReason`, `RetryGate`,
`recorded_denial_reason`, `RETRY_NOT_BEFORE_NOT_REACHED`, `AggregationVerdict`,
`SlotRetryStatus`, `REASON_SLOT_FAILED`, `build_aggregation_input`,
`COMPAT_NOT_APPLICABLE`, `DIAG_ID`/`OTHER_DIAG_ID`/`THIRD_DIAG_ID`,
`configuration_snapshots.freeze`/`get`, `CountingUnitOfWork`; for the
supervised flow exactly the binding table of §7.1.2: `Stage5InvocationLifecycle`
and `RequestMaterial`, `build_supervisor`, `TeeController`, `RecordingObserver`,
`RealtimeMonotonicClock`, `supervised_catalog_entry_for`,
`SCRIPTED_SUPERVISOR_INSTANCE_ID` (`doubles.supervision`), `SCENARIOS`/`Scenario`
(`contract.scenarios`), `DEFAULT_NEGOTIATED`, `FAKE_RUNTIME_VERSION`,
`FAKE_OPERATING_SYSTEM`, `OBSERVATION_VALIDITY` (`contract.harness`),
`WindowsProcessController`, `ThreadSafeCancellationToken`, `plan_command_paths`,
`PathPreflight`, `SupervisionTraceKind`, `reconcile_invocations`,
`AdapterCommand`, `DescribeRequestPayload`, `request_hash_of`,
`request_material_hash`, `PROTOCOL_LIMITS_DEFAULT`, `MAX_VALIDATION_RESULT_BYTES`,
`MAX_DESCRIPTOR_OUTPUT_BYTES`, `parse_result_manifest`, `parse_validation_result`,
`parse_bootstrap_descriptor`, `reconcile_describe`, `CandidateObservation`,
`CORE_PROTOCOL_SUPPORT`, `describe_availability_observation`, `token_present`,
`sha256_bytes`, `AttemptTokenMaterial`, `create_invocation`, `enrich_invocation`,
`apply_command_semantic_outcome` and the Stage 6 fake `fake_adapter.py` (through
the catalogue entry). Not consumed: `OfflineCommandHarness`, `ProductionSupervision`,
`supervised_strategy.py`, `supervision_scenarios.py`, `SeedingDiagnosticRecorder`,
`InMemoryReconciliationSource`, `InMemoryBackingStore`, `InMemoryUnitOfWork`.
**Experiment construction over SQLite (reading 22).** Both flows create,
validate, freeze and queue their experiment through their own composition
helper with a configuration-backed draft — the durable flow with
`config_backed_draft(retrying_config())` (the shared alpha/beta slots), the
supervised flow with `supervised_draft(ApplicationConfig(), row.adapter_name, strategy_version_hash=version.content_hash, dataset_version_hash=descriptor.content_hash)`
(§7.1.1: one slot naming the row's adapter at `FAKE_ADAPTER_VERSION` with
`FAKE_ENGINE`, the identities the fake-adapter catalogue and dispatcher
recognise, citing the registered records' hashes; the two drafts are distinct
on purpose and neither is fed to the other flow). In both:
`create_experiment(ExperimentCreationRequest(spec_draft=<draft>, material_base_configuration_hash=material_base_configuration_hash(config)))`,
`transition_experiment(→ VALIDATED)`, `configuration_snapshots.freeze(experiment_id, snapshot_configuration(config))`
in its own committed transaction, then
`queue_experiment(ExperimentQueueRequest(expected_revision=1, config_derived_retry_policy=retry_policy_from_config(config.scheduler.retry), material_base_configuration_hash=material_base_configuration_hash(config), slot_compatibility=sample_slot_compatibility(<draft>)))`.
**The supervised composition (Option B, §7.1.2).** `SupervisedSqliteFlow`
(`tests/persistence_support/supervised.py`) exercises the eight selected
Stage 6 rows of §7.1.2 — reusing the scenario data (`contract.scenarios`), the
fake executable and catalogue identities (`doubles.supervision`), the canonical
builders, the command-path contract (`plan_command_paths`) and the production
supervision and application components — and binds every persistence-dependent
component to the SQLite test database through the binding table: `SqliteUnitOfWork`
under `CountingUnitOfWork`, `SqliteDiagnosticRecorder`, the Task 3/4 writers
and repositories, `SqliteReconciliationSource`. It reuses **no**
`OfflineCommandHarness` row-driver method and does not subclass that class:
the harness and `ProductionSupervision.supervise` are bound to
`InMemoryBackingStore`/`InMemoryUnitOfWork`/`SeedingDiagnosticRecorder(harness.store)`
with no unit-of-work or recorder seam (`tests/contract/harness.py::OfflineCommandHarness.__init__`
and `_unit_of_work`; `supervised_strategy.py::ProductionSupervision.supervise`),
and `tests/contract/*`, `tests/doubles/*` and `tests/fake_adapters/*` stay
unedited (§10). `new_experiment` (hard-coded `material_base_configuration_hash=MATERIAL_HASH`,
which no `ApplicationConfig` yields) and `drive()` are therefore not reached
either. The fake-adapter dispatcher, the catalogue and the production
identities are not changed. The durable flow uses `retrying_config()`; the
supervised flow, which creates no successor, uses `ApplicationConfig()`.
**Diagnostic identities in the durable flow.** Every diagnostic is built by
the doubles' factory with the identities the flow actually drew:
`sample_diagnostic(<id>, experiment_id=flow.experiment_id, run_id=<that run>, invocation_id=<that run's invocation>, …)`;
the identifiers are the doubles' three constants assigned per attempt, not by
call order — `DIAG_ID` for slot A's first attempt, `OTHER_DIAG_ID` for slot
B's attempt, `THIRD_DIAG_ID` for slot A's successor — so no identity carries another
run's correlation facts and every one satisfies
`RetryEvaluationSnapshot._validate_primary_diagnostic` (`experiment_id` and
`run_id` must equal the snapshot's when present). Slot B's diagnostic is
`error_code=COMPAT_NOT_APPLICABLE` (`adapters.diagnostics`), category
`COMPATIBILITY`, `retriable=False`, carrying its `VALIDATE` invocation.
**Interfaces produced.** None in `src`; the two test-support compositions
`DurableFlow` (`tests/persistence_support/harness.py`) and
`SupervisedSqliteFlow` (`tests/persistence_support/supervised.py`, §7.1.2).
**Owned schema/migration/configuration changes.** None.
**Guard/dependency transitions.** None.

- [ ] **Step 1: Focused RED.**

```python
def test_the_two_slot_flow_over_sqlite_aggregates_to_failed(tmp_path: Path) -> None:
    flow = DurableFlow.open(tmp_path, config=retrying_config())
    try:
        flow.register_strategy_and_dataset()
        # create_experiment receives config_backed_draft(flow.config) and
        # material_base_configuration_hash(flow.config); the flow freezes
        # snapshot_configuration(flow.config) while VALIDATED and only then calls
        # queue_experiment with the same hash and derived policy (reading 22).
        flow.create_validate_and_queue_experiment()
        assert flow.frozen_snapshot() == snapshot_configuration(flow.config)
        flow.create_attempts_for_every_slot()  # RUNNING at revision 4
        # Slot B: its VALIDATE invocation exits 20 and the run leaves VALIDATING
        # as NOT_APPLICABLE with a COMPATIBILITY primary (OTHER_DIAG_ID);
        # NOT_APPLICABLE maps to no retry state, so the slot needs no decision.
        run_b = flow.drive_first_attempt_to_not_applicable(SLOT_B)
        assert run_b.state is _R.NOT_APPLICABLE
        # Slot A: READY, launched, RUNNING, then FAILED with a retriable primary
        # (DIAG_ID) recorded before the transition.
        run_a = flow.drive_first_attempt_to_failed(SLOT_A)
        decision = flow.evaluate_retry(run_a)
        assert decision.outcome is RetryDecisionOutcome.ALLOWED
        assert decision.reserved_successor_attempt_number == 2
        assert decision.retry_not_before_utc == run_a.updated_at_utc + timedelta(
            seconds=30
        )
        assert _code(flow.create_successor(run_a)) == RETRY_NOT_BEFORE_NOT_REACHED
        flow.advance_clock_to(decision.retry_not_before_utc)
        successor = _ok(flow.create_successor(run_a))
        assert (successor.attempt_number, successor.predecessor_run_id) == (
            2,
            run_a.run_id,
        )
        failed_successor = flow.drive_run_to_failed(successor)  # THIRD_DIAG_ID
        exhausted = flow.evaluate_retry(failed_successor)
        assert exhausted.outcome is RetryDecisionOutcome.DENIED
        assert exhausted.denial_reason is RetryDenialReason.ATTEMPT_BUDGET_EXHAUSTED
        # The successor's own row decides; the predecessor's ALLOWED row is history.
        assert exhausted.predecessor_run_id == failed_successor.run_id
        assert flow.retry_decision(run_a).outcome is RetryDecisionOutcome.ALLOWED
        assert flow.slot_retry_statuses() == {
            SLOT_A: SlotRetryStatus.DENIED,
            SLOT_B: SlotRetryStatus.NO_DECISION_REQUIRED,
        }
        before = flow.experiment()
        assert (before.state, before.revision) == (_E.RUNNING, 6)
        result = flow.aggregate()  # the real aggregate_experiment
        assert (result.verdict, result.reason_codes) == (
            AggregationVerdict.FAILED,
            (REASON_SLOT_FAILED,),
        )
        after = flow.experiment()
        assert (after.state, after.revision) == (_E.FAILED, 7)
        replay = flow.aggregate()  # terminal replay: verdict only, no write
        assert (replay.verdict, replay.reason_codes) == (AggregationVerdict.FAILED, ())
        assert flow.experiment() == after
        report = flow.consistency_report()
        assert report.dangling_diagnostic_references == 0
        assert report.queued_without_snapshot == 0
        assert (report.causal_edge_mismatches, report.unresolved_causal_references) == (
            0,
            0,
        )
        assert flow.frozen_snapshot() == snapshot_configuration(flow.config)
        assert flow.run_states().isdisjoint(SUCCESS_ENGINE_RUN_STATES)
    finally:
        flow.close()


def test_an_unresolved_failed_slot_keeps_the_experiment_running(
    tmp_path: Path,
) -> None:
    # Negative control for the classifier boundary: slot B ends FAILED and is
    # never evaluated, so its status is DECISION_UNRESOLVED (Row 3) and the real
    # aggregate_experiment returns NOT_YET_TERMINAL without writing.
    flow = DurableFlow.open(tmp_path, config=retrying_config())
    try:
        flow.register_strategy_and_dataset()
        flow.create_validate_and_queue_experiment()
        flow.create_attempts_for_every_slot()
        flow.drive_first_attempt_to_failed(SLOT_B)  # OTHER_DIAG_ID; no evaluate_retry
        run_a = flow.drive_first_attempt_to_failed(SLOT_A)
        decision = flow.evaluate_retry(run_a)
        flow.advance_clock_to(decision.retry_not_before_utc)
        failed_successor = flow.drive_run_to_failed(_ok(flow.create_successor(run_a)))
        assert (
            flow.evaluate_retry(failed_successor).outcome is RetryDecisionOutcome.DENIED
        )
        assert flow.slot_retry_statuses()[SLOT_B] is SlotRetryStatus.DECISION_UNRESOLVED
        before = flow.experiment()
        result = flow.aggregate()
        assert (result.verdict, result.reason_codes) == (
            AggregationVerdict.NOT_YET_TERMINAL,
            (),
        )
        assert flow.experiment() == before  # RUNNING at the same revision
    finally:
        flow.close()


def test_the_default_retry_configuration_denies_the_automatic_successor(
    tmp_path: Path,
) -> None:
    # Negative control (§7.1.1): ApplicationConfig() is unchanged and its policy
    # (one attempt, no retry states) denies the very successor the flow above
    # reaches under retrying_config(); the denial comes from the policy gates.
    flow = DurableFlow.open(tmp_path, config=ApplicationConfig())
    try:
        flow.register_strategy_and_dataset()
        flow.create_validate_and_queue_experiment()
        flow.create_attempts_for_every_slot()
        run_a = flow.drive_first_attempt_to_failed(SLOT_A)
        decision = flow.evaluate_retry(run_a)
        assert decision.outcome is RetryDecisionOutcome.DENIED
        assert decision.denial_reason is recorded_denial_reason(
            (RetryGate.ATTEMPT_BUDGET, RetryGate.TERMINAL_STATE)
        )
        assert flow.attempt_count(SLOT_A) == 1
    finally:
        flow.close()


def test_a_conformant_run_row_persists_through_the_supervisor(
    supervised_sqlite_flow: SupervisedSqliteFlow,
) -> None:
    flow = supervised_sqlite_flow
    flow.describe(flow.scenario("row01-conformant-describe"))  # S-1 mints AVAIL_A
    row = flow.scenario("row03-conformant-run")  # S-3
    run = flow.prepare_run(row)  # registries, experiment, freeze, queue, READY
    before = flow.database_sha256()
    outcome = flow.invoke(row, run)  # the production supervisor over SQLite
    assert flow.max_open_during_child == 0
    semantic = flow.conclude(row, run, outcome)  # parse + semantic outcome
    assert semantic is not None
    invocation_id = outcome.command_result.invocation.invocation_id
    # Fresh session opened after the writer's last operation returned.
    invocation = flow.fresh_invocation(invocation_id)
    assert (invocation.state, invocation.native_exit_value) == (_C.EXITED, 0)
    assert flow.fresh_run(run.run_id).state is _R.RUNNING  # eligible, not final
    events = flow.fresh_events(invocation_id)
    assert len(events) == row.accepted_events == 5
    assert [event.sequence for event in events] == sorted(e.sequence for e in events)
    assert events == outcome.command_result.accepted_events
    assert flow.consistency_report().dangling_diagnostic_references == 0
    # Memory-bound negative control: an independent stdlib connection on the
    # same file sees the rows, and the file's bytes changed.
    assert flow.independent_counts(invocation_id) == (1, 5)
    assert flow.database_sha256() != before
    assert flow.token_absent_everywhere(run.run_id)


@pytest.mark.parametrize(
    ("name", "invocation_state", "run_state"),
    [
        ("row27-cancellation-run", _C.CANCELLED, _R.CANCELLED),  # S-6
        ("row26-process-timeout-run", _C.TIMED_OUT, _R.TIMED_OUT),  # S-7
    ],
)
def test_core_won_terminals_are_recorded_by_the_sqlite_lifecycle(
    supervised_sqlite_flow: SupervisedSqliteFlow,
    name: str,
    invocation_state: CommandInvocationState,
    run_state: EngineRunState,
) -> None:
    flow = supervised_sqlite_flow
    flow.describe(flow.scenario("row01-conformant-describe"))
    row = flow.scenario(name)
    run = flow.prepare_run(row)
    outcome = flow.invoke(row, run)  # no epilogue: a core-won terminal
    assert flow.max_open_during_child == 0
    invocation_id = outcome.command_result.invocation.invocation_id
    invocation = flow.fresh_invocation(invocation_id)
    assert (invocation.state, invocation.cleanup_complete) == (invocation_state, True)
    stored_run = flow.fresh_run(run.run_id)
    assert stored_run.state is run_state
    primary = flow.fresh_diagnostic(stored_run.primary_terminal_diagnostic_id)
    assert primary.error_code == row.primary_code  # recorded by the lifecycle
    assert flow.consistency_report().dangling_diagnostic_references == 0


def test_the_reopened_database_holds_every_supervised_row(tmp_path: Path) -> None:
    flow = SupervisedSqliteFlow.open(tmp_path, config=ApplicationConfig())
    ids: dict[str, str] = {}
    try:
        flow.describe(flow.scenario("row01-conformant-describe"))
        for name in (
            "row02-conformant-validate",
            "row03-conformant-run",
            "row05-unsupported-capability-validate",
            "row28-exit-40-run",
            "row27-cancellation-run",
            "row26-process-timeout-run",
        ):
            row = flow.scenario(name)
            run = flow.prepare_run(row)
            outcome = flow.invoke(row, run)
            flow.conclude(row, run, outcome)
            ids[name] = run.run_id
    finally:
        flow.close()  # disposes the engine and drops every application object
    reopened = SupervisedSqliteFlow.reopen(tmp_path)  # S-8: new objects, same file
    try:
        expected = {
            "row02-conformant-validate": _R.READY,
            "row03-conformant-run": _R.RUNNING,
            "row05-unsupported-capability-validate": _R.NOT_APPLICABLE,
            "row28-exit-40-run": _R.FAILED,
            "row27-cancellation-run": _R.CANCELLED,
            "row26-process-timeout-run": _R.TIMED_OUT,
        }
        assert {n: reopened.fresh_run(r).state for n, r in ids.items()} == expected
        assert reopened.fresh_observation(AVAIL_A).available is True
        report = reopened.consistency_report()
        assert report == ConsistencyReport(*([0] * 8))  # all eight counts zero
        assert reopened.reconcile().entries == ()  # nothing left to reconcile
        assert reopened.run_states().isdisjoint(SUCCESS_ENGINE_RUN_STATES)
    finally:
        reopened.close()
```

  The durable flow, step by step against the committed operations (every
  step is a real operation over `SqliteUnitOfWork`; the fixture writes nothing
  but the recorder's diagnostics and the writer's observations, exactly as the
  Stage 5 flow seeds them): (1) `DurableFlow.open` migrates a `tmp_path`
  database and composes `SqliteUnitOfWork`, `SqliteDiagnosticRecorder`,
  `FixedClock(INSTANT)` and a sequential identity source; (2) `create_experiment`
  → `DRAFT` at revision 0 with the two shared slots and
  `retry_policy_from_config(retrying_config().scheduler.retry)` (two attempts,
  `(FAILED,)`, 30 s); `transition_experiment` → `VALIDATED` at 1; `freeze`;
  `queue_experiment` → `assert_queue_freeze` proves the two equalities from the
  request and §4.3.1 step d′ proves them from the stored snapshot → `QUEUED`
  at 2; (3) `create_attempt` for `SLOT_A` (→ `RUNNING` at 3, run A `PENDING`
  attempt 1) and `SLOT_B` (4); run edges never bump the experiment;
  (4) **slot B, the no-decision terminal:** `transition_run` → `VALIDATING`;
  its `VALIDATE` invocation `PENDING` → `STARTING` → `RUNNING` → `EXITED` with
  `native_exit_value = 20` (the frozen exit table's `NOT_APPLICABLE` category);
  the recorder records `sample_diagnostic(OTHER_DIAG_ID, error_code=COMPAT_NOT_APPLICABLE, category=COMPATIBILITY, retriable=False, experiment_id=…, run_id=run_b, invocation_id=<that VALIDATE invocation>)`;
  `transition_run` `VALIDATING → NOT_APPLICABLE` (a permitted generic edge;
  the five non-success terminals require the primary, and the observation stays
  absent because the run never reached `READY`) — `retry_terminal_state_of(NOT_APPLICABLE)`
  is `MISSING`, so the slot's retry status is `NO_DECISION_REQUIRED` and no
  `evaluate_retry` is ever called for it; the frozen compatibility (`SUPPORTED`)
  is untouched, so the slot is a *late* `NOT_APPLICABLE`; (5) **slot A's first
  attempt:** the observation minted from `describe_availability_observation`
  is persisted through the writer, `VALIDATING` (its `VALIDATE` invocation
  exits 0) → `READY` → the `RUN` invocation launches → `RUNNING` → the
  invocation `EXITED` (40); the recorder records
  `sample_diagnostic(DIAG_ID, experiment_id=…, run_id=run_a, invocation_id=<that RUN invocation>, retriable=True)`
  (category `ENGINE_RUNTIME`, not hard-blocking) before `transition_run` →
  `FAILED` with `primary_terminal_diagnostic_id`; the predecessor's terminal
  instant is its `updated_at_utc`; (6) `evaluate_retry` with
  `expected_experiment_revision=4` and the run's revision: the snapshot has
  `created_attempt_count = count_attempts(E, SLOT_A) = 1 < 2`, mapped terminal
  state `FAILED ∈ (FAILED,)`, a retriable primary whose `experiment_id` and
  `run_id` equal the snapshot's, the canonical closure
  `{(ENGINE_RUNTIME, ENGINE.RUNTIME_FAILURE)}` with no hard block, experiment
  `RUNNING`, no availability requirement (not `UNAVAILABLE`) → every gate passes
  → `ALLOWED`, `reserved_successor_attempt_number = 2`,
  `retry_not_before_utc = terminal instant + 30 s`, experiment bumped to 5;
  (7) `create_successor` before that instant → `RETRY.NOT_BEFORE_NOT_REACHED`
  (C-24 proves the persisted delay); `FixedClock.advance` to the instant;
  `create_successor(expected_experiment_revision=5, request_hash=OTHER_REQUEST_HASH)`
  → attempt 2 with `predecessor_run_id = run_a`, `retry_reason = FAILED`,
  adapter and engine copied, experiment 6; (8) the successor is driven to
  `FAILED` as in (5) with `THIRD_DIAG_ID` and its own `RUN` invocation;
  `evaluate_retry` on **the successor** (its own predecessor key
  `(SLOT_A, successor.run_id)`) → `DENIED`, `ATTEMPT_BUDGET_EXHAUSTED`
  (`created_attempt_count = 2`, not `< 2`), a `DENIED` row that bumps nothing;
  the first attempt's `ALLOWED` row is immutable history and is not the
  successor's decision; no third attempt exists; (9) before aggregation: slot
  A's latest attempt is `FAILED` with its own `DENIED` row (status `DENIED`),
  slot B's latest attempt is `NOT_APPLICABLE` (status `NO_DECISION_REQUIRED`),
  the experiment is `RUNNING` at 6; `aggregate_experiment(expected_revision=6)`:
  Rows 1–3 do not fire, `S = ∅`, `N = {B}` (late), Row 4 needs `N` to be every
  slot, so Row 5 decides — `FAILED` with exactly `("EXPERIMENT.SLOT_FAILED",)`
  (a late `NOT_APPLICABLE` beside a failure contributes no code) — and the
  experiment is swapped to `FAILED` at 7; `COMPLETED_WITH_WARNINGS` is
  unreachable here (Row 7/8 need a success member); (10) a second
  `aggregate_experiment` on the terminal record returns the verdict `FAILED`
  with **empty** reason codes, reads no clock and writes nothing (the record and
  revision are unchanged). Two negative controls: under `retrying_config()` with
  slot B driven to `FAILED` (`OTHER_DIAG_ID`, its `RUN` invocation) and never
  evaluated, `_retry_status` reads no decision row for `(SLOT_B, run_b)` →
  `DECISION_UNRESOLVED` → Row 3 → `NOT_YET_TERMINAL` with empty reason codes
  and no write, the experiment still `RUNNING` at 6 — the original round-5
  defect, now asserted as the classifier's boundary; and under
  `ApplicationConfig()` steps (1)–(3), (5) and (6): gates `ATTEMPT_BUDGET`
  (`1 < 1` is false) and `TERMINAL_STATE` (`FAILED ∉ ()`) fail, the recorded
  reason follows the fixed precedence (`recorded_denial_reason`), and the
  attempt count stays 1 — the successor the positive flow reaches is
  unreachable under the unchanged defaults.
  Planning evidence (§7.1.1): the application-flow probe executed this
  sequence — the same method names, the fence's constructors, the committed
  operations over `InMemoryUnitOfWork`/`InMemoryBackingStore`, `FixedClock` and
  `SequentialIdentitySource` — through both aggregations and both negative
  controls. Its recorded adaptations for the in-memory kind: the recorder is
  `InMemoryBackingStore.seed_diagnostic`, the observation writer is
  `seed_availability_observation`, and `freeze`/`frozen_snapshot()`/
  `consistency_report()` are persistence-only steps with no in-memory
  counterpart, so they remain unexecuted implementation obligations of Tasks
  3–4 and 7. The probe proves application-flow reachability, not a SQLite
  behaviour.

  plus, for the supervised flow, the storage obligations of every §7.1.2 row
  not shown above: S-1 (the `DESCRIBE` invocation `EXITED` with verdict
  `DESCRIBED`; the observation minted from `describe_availability_observation`
  persisted through the writer and read back equal through
  `availability_observations.get(AVAIL_A)`; an `ADAPTER`-owned owner row
  registered and re-read), S-2 (`VALIDATED_READY`: the run `READY` with
  `availability_observation_id == AVAIL_A`, so the foreign key to S-1's row
  held; `list_events` = 2), S-4 (`NOT_APPLICABLE` through the real supervisor
  and semantic outcome with the `COMPAT.NOT_APPLICABLE` primary resolving),
  S-5 (`FAILED` with the `ENGINE.RUNTIME_FAILURE` primary resolving and 2
  events); for every supervised row: the registered `StrategyVersion` and
  `DatasetDescriptor` round-tripped through `get_by_hash` and their
  `content_hash` values cited by the experiment's spec (the "resolve before
  queueing" reading of §3.3.1; no foreign key), the raw token absent from every
  `TEXT` column and JSON snapshot (a full-text scan for the attempt token the
  flow held), `RunManifest` and success states absent, every count of
  `consistency_report()` zero after the caller records the semantic outcome's
  diagnostics (the causal edges among them present in `diagnostic_causes`,
  C-31's convergence at production scale), the experiment's frozen snapshot
  unchanged by every later transition (`configuration_snapshots.get` equal
  before and after), and `counting.max_open == 1` over the whole flow. In the
  durable flow: `register_strategy_and_dataset()` registers
  `sample_strategy_version()` and `sample_dataset_with_partitions()` and asserts
  the `get_by_hash` round trips (its spec keeps the fixture hash constants —
  no foreign key, §3.3.1).
- [ ] **Independent review addendum.** Readings 22 and 23 against the composed
  calls: the freeze precedes `queue_experiment`, the request's hash and policy
  derive from the same `ApplicationConfig` (`retrying_config()` or
  `ApplicationConfig()`, never a changed default), no experiment is built
  through `OfflineCommandHarness.new_experiment` or `drive()`, the supervised
  experiment's slot names the row's adapter, the successor is reached only
  through `evaluate_retry` and `create_successor`, the successor's decision is
  its own row, every slot is resolved before `aggregate_experiment` is asserted
  terminal, every diagnostic carries the drawn identities, and no test writes
  `diagnostic_causes` or the snapshot columns directly; §7.1.2 against
  `supervised.py`: every binding-table component is the named symbol with the
  named signature, `SupervisedSqliteFlow` subclasses nothing from
  `tests/contract`, the AST scan finds none of the forbidden names, every
  supervised write is asserted through a fresh session **and** the independent
  connection, no transaction is open across `invoke`, and the S-8 reopen uses
  no object from the closed flow.
- [ ] **Step 2: Run the focused set and confirm every new test fails for the
  expected reason** (the composition helpers absent).
- [ ] **Step 3: Minimum GREEN.** The two test modules and their helpers.
- [ ] **Step 4: Focused GREEN.** `tests\integration\persistence tests\integration\experiments tests\integration\process_supervision -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `pytest-all` alone (the first complete run with every Stage 8
module counted), then `scripts/verify.ps1` alone.
**Windows-specific tests.** The supervised rows launch real children through
the production controller; every launch identity terminated and absent in
`finally:` as the Stage 7 suites do.
**Minimum passing evidence.** Both flows green; `pytest-all` green at or above
the baseline coverage; `verify.ps1` green with eleven stages.
**Security and boundary review.** No success run state, no `RunManifest`, no
finalization, no `AuditSink`; the token scan finds nothing; the child never
receives the database path (the database lives at `tmp_path/db/`, every
`AdapterCommand` path under `tmp_path/supervision/`); an AST scan of
`tests/persistence_support/supervised.py` finds no import of
`contract.harness.OfflineCommandHarness`, `doubles.experiments.InMemoryBackingStore`,
`doubles.experiments.InMemoryUnitOfWork`, `doubles.supervision.SeedingDiagnosticRecorder`,
`doubles.supervision.InMemoryReconciliationSource`, `supervised_strategy` or
`supervision_scenarios`, no class deriving from a `tests/contract` class and
no `.store` attribute access; `max_open_during_child == 0` on every row and
`counting.max_open == 1` over each flow.
**Independent review.** §4.1 flow matrix against the composed calls; §1.4 row 7
(caller obligation exercised); no `src` change.
**Commit message.** `feat: compose the application operations over sqlite persistence`

### Task 8 — Stage 8 boundary guard, documentation and Stage 8 status

**Objective.** Pin the Stage 8 surface and record completion: the Stage 8
guard, the focused checks in the verification guide, README and roadmap status,
and every status pin of §2.6 (Status pins).
**Prerequisites.** Task 7 committed; its hash known.
**Files created.** `tests/safety/test_stage8_boundaries.py`.
**Files modified.** `README.md`, `docs/development/verification.md`,
`docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md`,
`tests/safety/test_stage3_boundaries.py`, `tests/safety/test_stage5_boundaries.py`,
`tests/safety/test_stage7_boundaries.py`, `tests/safety/test_gitnexus_development_tooling.py`.
**Interfaces consumed.** None.
**Interfaces produced.** None.
**Guard/dependency transitions.** §2.6 Status pins; the Stage 8 guard.

- [ ] **Step 1: Focused RED.** The Stage 8 guard asserts: `STAGE8_SOURCE_FILES`
  (the 15 paths of §2.6, `len == 15`, disjoint from the Stage 5/6/7 sets); the
  `sqlalchemy`/`alembic` root confinement to the exact module sets of §2.6;
  `persistence` imports only the module set of the header's dependency bullet
  (AST over every `crypto_lab.*` import); `datasets/ports.py` and
  `strategy/ports.py` import only `domain` and their own package; no persistence
  module imports `sqlite3`, `os`, `sys`, `time`, `types`, `logging`, `threading`,
  `asyncio`, `ctypes`, `queue`, `subprocess`; no persistence annotation names
  `AttemptToken`; no persistence identifier is `context`, `buffer`, `note`,
  `problem`; no persistence module defines a `_STAGE8_AND_LATER_NAMES` name; no
  persistence write path touches `diagnostic_ids` outside the mapped
  compare-and-swap (§1.5 note 5); the Alembic head equals `r0001_stage8_baseline`
  and the script directory holds exactly one revision; every `.py` under
  `migrations/versions` is `__init__.py` or `r0001_stage8_baseline.py`; the
  roadmap Stage 8 completion row, the Stage 9 deferred row, the approved-plan
  line, README and guide status blocks (positives), the Stage 7 forms
  (negatives), the hash rules of §2.6; the guide's Stage 8 focused-check
  sentences; no documentation surface says "exhaustiv", "sandbox" or "Stage 9
  has started".
- [ ] **Step 2: Run the focused set and confirm every new test fails for the
  expected reason** (the status prose absent; the Stage 7 pins still positive).
- [ ] **Step 3: Minimum GREEN.** The prose and the pin edits:
  README status line and paragraph ("Project 1 Stage 8 is complete. …
  implementation completed at `<Task 7 hash>`; the Stage 8 boundary guard and
  this status were added by the separate Task 8 commit, which is not the
  implementation hash. No schema was added: the closed 35-schema registry is
  preserved byte-identical; the relational schema has one Alembic head. Stage 9
  has not started."), the guide's "Stage scope" block ending "Stage 9 is not
  started.", the Stage 8 focused targets, the `_VERIFICATION_NON_GOALS`
  rewording, the roadmap header, plan sentence, Stage 7 row clause, Stage 8
  completion row (`Implementation complete at <Task 7 hash>`) and the plan line
  changed from "Planned" to "Approved".
- [ ] **Step 4: Focused GREEN.** `tests\safety tests\unit\test_schema_registry.py -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `scripts/verify.ps1` alone before the commit and again on
the fast-forwarded `main`, followed by the ownership-aware hygiene checks.
**Windows-specific tests.** None new.
**Minimum passing evidence.** The complete verifier green twice (branch and
merged `main`), eleven stages, two skips, coverage at or above the baseline.
**Security and boundary review.** Documentation names no sandbox claim; the
guide records the Stage 8 evidence (§9.3) and the two known limitations
(§1.4 rows 1 and 9) rather than erasing them.
**Independent review.** Every §2.6 status pin before/after; the guide prose
generated from guard constants where the guards pin it.
**Commit message.** `feat: add stage 8 boundaries, documentation and status`

---

## 9. Verification and acceptance

### 9.1 Commands

Focused, during red-green development (diagnostic only; `-o addopts=` disables
coverage); every target is a normalized repository-relative path under `tests/`,
the only shape the launcher's `pytest-focused` profile accepts:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\persistence -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\integration\persistence -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\property\test_persistence_codecs.py tests\unit\datasets tests\unit\strategy -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\experiments\test_port_contracts.py tests\safety tests\architecture -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\safety\test_stage8_boundaries.py tests\unit\test_schema_registry.py -q
```

Quality gates after every task: `ruff-format-all` (apply the printed diff by
hand), `ruff-check-all`, `mypy-all`, `schema-generate-check` and, from Task 2,
`migration-check` — this last profile is **new work of Task 2**, not an existing
command, and is cited only after that task lands:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 migration-check
```

Dependency gates (Task 1 only): the exact sequence of §2.8. The two acquisition
profiles are bootstrap evidence and never appear in a verification claim.

Complete, before any completion claim, alone on the host (no other pytest, no
reviewer agent, no other Python child running — the Stage 4 strategy-hashing
properties flake their hypothesis deadline under load, the Stage 7 suites launch
real children, and the Stage 8 lock tests measure bounded waits), from a shell
attached to a console:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

From Task 2 onward the verifier runs eleven steps (lock-check, sync,
ruff-format-all, ruff-check-all, mypy-all, schema-generate-check,
migration-check, pytest-all, build, schema-distribution, `git diff --check`).
Before every long run, `tasklist` proves no orphan `python.exe` from an earlier
fake-adapter launch or interrupted-writer child survives; a survivor is a defect
to investigate, never to kill and forget. After every long run the
ownership-aware hygiene checks record process probes (task-owned survivors and
suspended fixture processes must be zero), and the Stage 7 command-root check
counts only roots outside pytest's retained base temporary directories.

### 9.2 Serial order that stays flake-free

Focused suites → the task's independent review (no pytest running) →
`pytest-all` alone → `scripts/verify.ps1` alone → commit → (Task 8 only)
fast-forward `main` → merged-`main` verifier alone → hygiene checks. Reviewer
agents and the verifier never run concurrently. The known intermittent
open-handle-count assertion of the Stage 7 Windows suite is a recorded
verification risk: a rerun is performed alone once and recorded with both
outcomes; a later pass does not prove the assertion fixed, and no test is
altered for it.

### 9.3 Acceptance criteria

Stage 8 is complete only when all of the following hold with fresh offline
evidence:

1. `sqlalchemy` and `alembic` are runtime dependencies resolved through §2.8's
   gates; `uv.lock` records registry sources and SHA-256 hashes for every new
   artifact; `lock-check` and `sync` pass offline; the resolved SQLAlchemy is
   2.x and Alembic 1.x; no prohibited family entered the lock; the ledger records
   which gates ran.
2. A database opened by `open_database` has `journal_mode = wal`,
   `foreign_keys = 1`, `synchronous = 2` and the configured `busy_timeout` on
   every connection, verified by read-back; a refused open (foreign identity,
   corrupt file, missing directory, wrong revision state) leaves the file bytes
   unchanged and creates nothing (C-19, C-20, C-21).
3. The Alembic script directory has exactly one head, `r0001_stage8_baseline`;
   a migrated database has no metadata drift and exactly the pinned
   `sqlite_master` objects; `EMPTY`, `CURRENT`, `BEHIND`, `UNKNOWN` and
   `UNVERSIONED` are classified as §6.4 states and only `CURRENT` opens for a
   normal command; a failing revision rolls back to the prior revision (C-22);
   `migration-check` is a verifier step.
4. Every mapped canonical record round-trips losslessly through its codec
   (property-tested), `MISSING` is `NULL` and never `null`, Decimal stays
   canonical text, every timestamp survives to the microsecond, and a corrupted
   row is refused on egress as `CORE.INVARIANT_VIOLATION`.
5. Every port method of §4.3 returns exactly the documented `Success` or
   `Failure`; a missing identity is `CORE.INVARIANT_VIOLATION` containing
   `does not exist`; a zero-row compare-and-swap, a duplicate identity, an
   index collision, a busy timeout and a stale-snapshot refusal are all
   `PERSISTENCE.CONCURRENCY_CONFLICT` at the call, never an exception and never
   first at `commit()`; a refused write publishes nothing and leaves the
   transaction usable (the shared contract cases prove it on both kinds); every
   compare-and-swap of the three repositories refuses in the order of §4.3.1 —
   pre-read, missing → conflict, stale → conflict, wrong step → invariant, then
   the conditional update whose zero rows or refused promotion is a conflict —
   with each refusal leaving the target row unchanged and the pre-read
   observing the transaction's own earlier writes (C-30, the retained contract
   assertions on both kinds).
6. Every multi-row operation of §4.1 commits both rows or neither (C-6, C-10;
   C-11 for `create_successor`, whose successor row and experiment bump land
   together in order (a) and neither lands in order (b) against the labelled
   terminal compare-and-swap winner — the aggregation half of C-11 is the measured
   non-competition of classifier row 3, not an aggregation write); the read set is
   protected without a revision move (C-12, whose mover is the persistence-owned
   snapshot freeze of the experiment row with the revision unchanged); the driver
   reruns exactly once (C-5, C-8, C-13); a multi-statement repository method
   whose later statement is refused leaves nothing of itself staged (C-29,
   reading 21).
6a. Slot identity is experiment-scoped (reading 7): two experiments may share
   a slot identifier and an attempt number, a second attempt with the same
   three-field identity is a conflict, and a run cannot reference a slot of
   another experiment (C-28); no `(logical_slot_id, attempt_number)` index
   exists.
6b. The `experiments` row owns the frozen configuration snapshot (reading 22):
   no `VALIDATED → QUEUED` swap succeeds without a frozen `ConfigSnapshot`
   whose base hash and derived retry policy agree with the frozen spec, the
   four columns are immutable from `QUEUED` onward and never cleared, the
   stored snapshot rebuilds as an equal `ConfigSnapshot` through its own
   validator, and `queued_without_snapshot` is zero after every production
   path (C-32, Task 7).
6c. Causal edges live in `diagnostic_causes` (reading 23): after every
   completed `record` call the relation equals the JSON edge set over recorded
   rows (`causal_edge_mismatches == 0`), both keys are `RESTRICT`, only the
   recorder writes the relation and it does so in the diagnostic's own
   transaction, and a refused edge leaves neither the diagnostic nor the edge
   committed (C-31).
7. Retry decisions: identical replay returns the stored winner without a write
   (C-9); a concurrent loser — identical or divergent — replays the durable
   winner after exactly one rerun and never writes a second row (C-7, C-8,
   reading 19); the durable `retry_not_before_utc` survives a reopen and is
   never reset (C-24).
8. Run events: identical replay returns the stored event, conflicting content
   and a reused `event_id` are conflicts, events belong to their invocation's
   run by foreign key, and every stored ledger is contiguous (C-14, Task 5).
9. The Stage 7 lifecycle scenarios and every restart row of Stage 7 plan section 8.5 hold over a
   reopened database with `SqliteReconciliationSource`; no row reaches `EXITED`
   without captured exit facts and none reaches a success state (C-23).
10. An interrupted writer process leaves no partial row and the database
    reopens with `quick_check = ok` (C-17); a read-only file fails writes as
    `PERSISTENCE.WRITE_FAILED` (C-18); a cross-process lock fails the writer as
    a bounded conflict; paths with spaces and Unicode components work.
11. The two-slot flow and the eight supervised rows of §7.1.2 compose over the
    durable repositories through the production supervisor and application
    operations with every persistence component bound to the SQLite test
    database (no in-memory store, unit of work, recorder or reconciliation
    source reachable), zero open transactions while a child runs, every
    supervised write verified through a fresh session and an independent
    connection on the same file (and after a close-and-reopen), zero dangling
    diagnostic references after the caller records the semantic outcome's
    diagnostics, the raw attempt token absent from every column, and no
    success state or `RunManifest` (Task 7).
12. Every closed-world guard of §2.6 holds at its reconciled value: 110 allowed
    source files, 29 import roots, 33 deferred definitions, seven live mutation
    cases, 13 infrastructure exemption pairs, five reader implementations, twelve
    `subprocess` importers, four runtime dependencies, 27 prohibited families,
    21 launcher operations, an eleven-step verifier, the registry at 35 with its
    four digest blocks, `HashingProfile` at 12, and every documentation pin at
    its Stage 8 successor.
13. `ruff-format-all`, `ruff-check-all`, `mypy-all`, `schema-generate-check`,
    `migration-check`, `pytest-all`, `build`, `schema-distribution` and
    `git diff --check` are clean offline; the complete verifier reports branch
    coverage of at least 98.42 percent with exactly the two approved skips.
14. No persistence module reads a clock, the environment or configuration;
    `sqlalchemy` and `alembic` are imported only by the modules §2.6 names;
    `process_supervision`, `experiments`, `adapters`, `domain`, `strategy`,
    `capabilities` and `configuration` never import `persistence`; no adapter
    receives a database path; no `experiments`, `adapters`,
    `process_supervision` or `domain` module is edited.

## 10. Rollback and completion

Each task ends in one commit, so any task is reverted with `git revert` of that
commit without touching another task; §2.6's guard edits travel in the same
commit as the module, name, root, pair or dependency change that trips them, so
a revert restores guard and source together. The highest-risk reversals are
Task 1 (the dependency change and the retired Stage 7 negative, both of which
every later task assumes) and Task 4 (the contract-suite split); both are
covered by the in-memory halves staying green unchanged. Task 7 is the
implementation commit whose hash the roadmap records; Task 8 touches no source
module, so reverting Task 8 alone returns the tree to a complete implementation
without its status prose.

Stage 1–7 files edited, all only as §2.6 tabulates: `pyproject.toml` and
`uv.lock` (Task 1); `scripts/invoke-uv.ps1` and `scripts/verify.ps1` (Task 2);
`tests/safety/test_stage3_boundaries.py` and `tests/unit/test_package_layout.py`
by every module-creating task (1–5) and the former by Tasks 2 and 8;
`tests/unit/process_supervision/test_supervisor_preflight.py` and
`tests/unit/process_supervision/test_restart_reconciliation.py` (the two
cross-pins) by Tasks 1–5; `tests/safety/test_stage5_boundaries.py` by Tasks 1–5
(pairs, reader census) and 8 (status import); `tests/safety/test_stage6_boundaries.py`
by Task 6; `tests/safety/test_stage7_boundaries.py` by Tasks 1, 6 and 8;
`tests/safety/test_project_dependencies.py`, `tests/safety/test_gitnexus_development_tooling.py`
and `tests/architecture/test_package_import_boundaries.py` by Task 1 (the
tooling test also by Task 8; the architecture test also by Tasks 3–5);
`tests/safety/test_uv_launcher.py` by Task 2; `tests/unit/experiments/test_port_contracts.py`
by Task 4; `src/crypto_lab/datasets/__init__.py` and `src/crypto_lab/strategy/__init__.py`
by Task 3; `docs/development/verification.md` by Tasks 1, 2, 6 and 8;
`README.md` by Tasks 2 and 8; the roadmap by Task 8. `tests/doubles/*`,
`tests/contract/*`, `tests/fake_adapters/*`, every `experiments`, `adapters`,
`process_supervision`, `domain`, `capabilities` and `configuration` module, and
every generated schema are not edited.

Stage 8 is complete when every criterion of §9.3 holds, the worktree is clean
and committed, the roadmap status table records `STAGE8_IMPLEMENTATION_COMMIT`
(the Task 7 commit, the last commit that adds Stage 8 behaviour) together with
the statement that the guard, documentation and status were added by the
separate Task 8 commit, README states "Stages 1-8 complete" and "Stage 9 has
not started.", and `docs/development/verification.md` records the Stage 8
focused checks and "Stage 9 is not started." No artifact finalizer,
`RunManifest`, `CandidateArtifact`, `ArtifactRef`, finalization journal or
audit sink exists anywhere in the tree.

The planning task that produced this document ends with the token
`STAGE8_PLAN_COMPLETE_AND_MERGED` only after the plan is reviewed, the unchanged
verifier passes on the plan commit and on the fast-forwarded `main`, and Stage 8
implementation has not begun.
