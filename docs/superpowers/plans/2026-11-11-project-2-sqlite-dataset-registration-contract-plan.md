# Project 2: temporary SQLite dataset-registration contract (bounded implementation plan)

**Status.** Revision 4 (revision 3's content with machine-local paths removed; revisions 1 to 3
were never published because the controller's publication-safety scan found a user-profile path
in revision 1's added lines),
proposed on 2026-11-11 under STANDING OWNER AUTHORIZATION
2026-11-10, AUTONOMOUS PROGRAMME DELIVERY. Awaiting independent plan APPROVE and advisor
DELEGATED_PLAN_ACCEPTED; this document is not an acceptance record. One test-only task.
Branch: project-2-sqlite-registration-contract, descended from accepted reader checkpoint
4d70f673a004b47883388fa45a0d93c8daa9167a. The controller commits the reviewed plan separately;
that plan commit becomes the implementation gate's base_commit. No Stage 9 merge prerequisite.
Dispatch remains NOT_READY until registration, environment and resource checks below pass.

**Authority and sources.** Paths below are repository-relative unless prefixed CTL or P2CTL.
Core source is pinned to main 079395bec70f1deda406d0ca14b2d4bf79aaf063 in the primary
checkout. P2 sources are read at 4d70f673 in the project-2-binance-kline-reader worktree.
CTL means the controller repository (its development worktree); P2CTL means the Project 2
controller root. Machine-local absolute paths are deliberately not written in this plan.

- P2CTL/config/mission_checkpoint.md:90-176: programme authority, priorities, readiness,
  two-worker cap, shared-contract ownership, serial verification and acceptance.
- CTL/README.md:458-496: delegated decision classes, four texts and journal provenance.
- docs/superpowers/plans/2026-11-09-project-2-offline-data-first-slice-implementation-plan.md:259-275:
  exclusions and section 1.4 obligation 1; actual inspected obligation is at lines 267-272.
- docs/superpowers/plans/2026-11-10-project-2-binance-kline-reader-plan.md:199-249,255-343:
  three Binance golden families, consumer tests, file-map syntax and acceptance route.
- offline_data/pyproject.toml:5-13,34-53,76-99: distribution 0.1.0, existing non-editable
  core path dependency, strict typing and unchanged 98.61 percent branch-coverage floor.
- src/crypto_lab/persistence/registries.py:824-952; src/crypto_lab/datasets/ports.py:1-51:
  concrete registration/read contract, transaction ownership and idempotence.
- src/crypto_lab/datasets/models.py:104-108,164-228,298-420;
  src/crypto_lab/datasets/hashing.py:14-98: model versions and metadata identity.
- src/crypto_lab/persistence/migration_runner.py:227-293,318-360;
  src/crypto_lab/persistence/database.py:561-570,652-654: temporary setup and cleanup.
- offline_data/tests/conftest.py:21-64; src/crypto_lab/domain/ports.py:33-49:
  reused golden IDs and the different clock protocols.
- offline_data/tests/safety/test_boundaries.py:64-91,830-844;
  offline_data/README.md:17-21,670-684: production census and pending-obligation wording.
- offline_data/scripts/invoke-offline-uv.ps1:168-198,221-328;
  offline_data/scripts/verify-offline.ps1:21-49: offline profiles and full gates.

## 1. Scope, placement decision and exclusions

Deliver an external consumer test of the real core SQLite repository using committed goldens.
Model decision under standing owner delegation; not a human message or approval:
class implementation_interpretation; summary: discharge obligation 1 in the P2 consumer suite.
Affected clauses: slice-1 section 1.4(1), lines 267-272, and section 1.3's ownership row,
line 259; README lines 17-21 and 681-684 repeat that placement.
Chosen solution: place the probe under offline_data/tests/integration/ on this isolated branch.
Workstream A retains sole authority over shared core code/contracts/migrations; Workstream B
owns only this test and its README explanation. No historical plan is rewritten.
Preserved guarantees: real repository, accepted core pin, golden inputs, temporary SQLite only,
hash and ordinal read-back, dependency direction P2 -> core, unchanged gates and exclusions.
This changes procedural placement, not production registration authorization.

Non-goals: production registration or a registration command; persistent application databases;
artifact finalization or DatasetArtifactOwner integration; P2-B1/P2-B2/P2-B3 lifts; reader fixes;
Parquet, downloads, network/data access, acquisition, engine installation/execution; shared
validation APIs; any core, schema, migration, lock, launcher or acceptance-subject change.
No Project 2 dependency enters Project 1's environment. No merge into Stage 9 or main in this task.

## 2. Consumed contract, fixed at accepted main

Import crypto_lab.persistence.registries.SqliteDatasetRepository, whose signatures are:
- __init__(self, connection: sqlalchemy.engine.Connection, *, clock: crypto_lab.domain.ports.Clock) -> None
- register(self, descriptor: DatasetDescriptor, partitions: tuple[DatasetPartition, ...]) -> Result[None]
- get_by_hash(self, content_hash: Sha256) -> Result[DatasetDescriptor]
- list_partitions(self, dataset_id: DatasetId) -> Result[tuple[DatasetPartition, ...]]

DatasetDescriptor, DatasetPartition and RawSourceProvenance are in crypto_lab.datasets.models;
descriptor and partition schema_version are 1.0.0. Sha256 and DatasetId are in
crypto_lab.domain.identifiers; Result, Success and Failure are in crypto_lab.domain.results.
crypto_lab.datasets.hashing.dataset_metadata_hash(descriptor, partitions) -> Sha256 uses
dataset-metadata/v1; validate_dataset_identity(descriptor, partitions) -> None raises ValueError
for inconsistent identity. The repository converts that refusal into a Failure, not an exception.
get_by_hash reads by metadata content hash; list_partitions takes dataset_id and orders by ordinal.
There is no get-by-ordinal method. The repository never commits; its caller commits.

Use the existing path dependency, never a source-path injection, core test-helper import or mock.
The checked core source at 4d70f673 equals the accepted pin; recheck before dispatch.
Goldens use column_schema_version 0.1.0 and normalized-ndjson/0.1.0, not Parquet.
Temporary setup uses crypto_lab.persistence.migration_runner.open_for_migration(path, *,
busy_timeout_ms, clock), apply_migrations(database), then open_database(path, *,
busy_timeout_ms, clock) on reopen; each returns Result. Connections come from the
SqliteDatabase.connection() context manager (autobegin; rolled back unless the test commits).
The packaged migration head at this pin is r0001_stage8_baseline. No migration implementation
is changed.

## 3. Test design

Create one parametrized integration module. Use sub_project_root to locate existing files.
Every case loads its committed descriptor.json, partitions.json and content_hash.txt documents:
- candles/golden: btcusdt-1m-clean; btcusdt-1m-gaps-duplicates.
- binance/golden: SYNTHETIC-BTCUSDT-1m-2024-12-31-ms;
  SYNTHETIC-BTCUSDT-1m-2025-01-01-us; SYNTHETIC-BTCUSDT-1m-gaps-duplicates-us.
These are stems under offline_data/tests/fixtures/, with the three suffixes above.
There are five families: the three Binance families plus both slice-1 families.

Strictly parse descriptor bytes with DatasetDescriptor.model_validate_json(..., strict=True)
and partitions with TypeAdapter(tuple[DatasetPartition, ...]).validate_json(..., strict=True).
Require recomputed dataset_metadata_hash to equal both descriptor.content_hash and the hash text;
run validate_dataset_identity. Never regenerate or edit goldens.

Each case creates its own absolute tmp_path / registry.sqlite3: all families reuse dataset and
partition IDs, so never register different families in one database or rewrite their IDs.
Use the real migration APIs, busy_timeout_ms=100 and a test-local deterministic core Clock.
Implement now_utc() and monotonic() (MonotonicInstant(0.0), from crypto_lab.domain.time);
the existing P2 fixed_clock lacks monotonic and must not be passed as a core Clock.
All helpers/fixtures stay local to the new module; conftest.py and core tests stay untouched.
Close databases in finally blocks, including setup/refusal paths; all SQLite/WAL/SHM files
remain under tmp_path. Do not open container relative_path or any real application registry.

For each family:
1. Assert register returns Success with value None; explicitly commit the connection.
2. Close and reopen through open_database, construct a fresh repository, read get_by_hash and
   list_partitions, and require Success plus complete typed equality with the parsed goldens.
3. Require canonical_json_bytes of read-back descriptor and partition list to equal the original
   golden bytes. Recompute identity from read-back values; preserve dataset/partition IDs,
   partition_ids correspondence, ordinals, relative_path, row counts, UTC bounds, both checksums,
   schema versions, normalization identity/version, source, timestamps, validation status,
   missing/duplicate intervals, diagnostic IDs, limitations and quality observations.
4. Explicitly check provenance source_name/source_version/source_record/source_hash against
   each family: ohlcv-csv/1.0.0 or binance-spot-kline-csv/1.0.0, the matching fixture filename,
   and SHA-256 of that committed valid.csv. Require descriptor raw_checksums to match ordered
   partition raw_checksum values, provenance equality and normalized checksum linkage.
   P2-B1 remains on every family; P2-B3 only on Binance families. Warning facts survive.
5. Require ordinals == tuple(range(len(partitions))) and returned IDs == descriptor.partition_ids.
   Existing goldens each contain one partition at ordinal 0; this proves that contract instance,
   not multi-partition sorting coverage.
6. Re-register the identical pair on a write connection, require Success[None], commit, then
   verify unchanged read-back and exactly one datasets row and one dataset_partitions row.
   Count rows on the repository's own connection with
   connection.exec_driver_sql("SELECT count(*) FROM datasets").scalar_one() and the same literal
   statement for dataset_partitions (literal SQL only, no f-string table names); import neither
   sqlalchemy nor crypto_lab.persistence.schema. Every row count in this section uses that
   mechanism. Helpers that need a connection take the SqliteDatabase and open
   with database.connection() as connection: inside, so the connection type is inferred under
   mypy strict and no annotation names a sqlalchemy type.

Negative controls, parametrized over the same families in fresh temporary databases:
- Change only descriptor.content_hash to a different valid lowercase 64-hex digest, keeping
  partitions untouched; strictly parse the changed document. Call register itself and require
  a Failure whose diagnostics tuple holds exactly one Diagnostic with error_code
  CORE.INVARIANT_VIOLATION and details == {"table": "datasets", "operation": "register",
  "identity": <the submitted content_hash>}. Require zero dataset/partition rows; the genuine
  pair must still register afterward.
- After genuine registration, strictly re-parse a descriptor with only created_at_utc advanced
  one second: mutate the parsed JSON object's created_at_utc key (imported_at_utc holds the same
  literal and must stay unchanged; never a bare bytes replace of the timestamp). Prove its
  recomputed hash is unchanged (creation time is excluded), then require
  register to refuse the different descriptor under that same hash with the same invariant code.
  Commit/reopen and require the original records and counts unchanged.
Never expect identical duplicate registration to fail. Check structured diagnostics, not driver
message text. Mutations are in-memory test values; no new committed fixture files or dependencies.

## 4. Task decomposition

### Task 1 - Prove golden dataset registration through the real SQLite repository

**Objective.** Implement section 3 and document the bounded placement and evidence.

**Prerequisites.** Independently reviewed, advisor-accepted plan committed on the new branch;
gate pinned to that commit; registered worktree/branch/refspec and unique mission identity;
both environments synchronized offline; launcher binding and resource preflight passed.
No Stage 9 merge, network acquisition or production interface is required.

**Files created.** `offline_data/tests/integration/test_sqlite_dataset_registration.py`.

**Files modified.** `offline_data/README.md`.

**Boundary guard.** No production module is added: the census scans the production package,
not integration tests. offline_data/tests/safety/test_boundaries.py stays unchanged and runs
in the focused set. No census, import allowlist, no-write, dependency or purity guard is weakened.
If implementation unexpectedly needs a production module, stop for a reviewed scope amendment;
that amendment must include the exact census file before any such module is added.

**README.** Add a `###` subsection "SQLite registration contract test (temporary database only)"
at the end of `## Placement: outside the core's dependency and runtime boundary` (README lines
33-48); update the `## Interim format and pending obligations` bullet at lines 681-684 with the
test location, core pin, focused command, the section 1 delegation and the temporary-only
registration limit; and revise the pending paragraph at README lines 17-21 so it names this
test's placement (offline_data/tests/integration/test_sqlite_dataset_registration.py, under the
delegated decision in section 1) in place of "owned by Workstream A". No text outside those
three places changes: do not change the Status paragraph (README lines 3-7) or the task table
(lines 9-15); this task's own acceptance is recorded in controller evidence only. Preserve the
remaining finalization, Parquet and real-source obligations, and record acceptance/publication
provenance in controller evidence rather than pretending this draft has passed.

**Execution.** From the registered worktree root, worker commands use only:
```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/invoke-offline-uv.ps1 pytest-focused -o addopts= tests/integration/test_sqlite_dataset_registration.py tests/integration/test_core_contract_roundtrip.py tests/safety/test_boundaries.py -q
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/invoke-offline-uv.ps1 ruff-format-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/invoke-offline-uv.ps1 ruff-check-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/invoke-offline-uv.ps1 mypy-all
```
The format profile checks only. Hand-edit authorized files to fix formatting.
No direct uv/python/pytest route; lock-check and sync are operator/controller prerequisites.
This test-only task adds probes of existing behavior; do not manufacture a production defect
to obtain RED. Tampered inputs and conflicting registration are the load-bearing negative controls.

- [ ] Implement local helpers and the complete positive/negative matrix; run the focused set.
- [ ] Update the bounded README sections; run the three quality profiles, all green.
- [ ] Controller runs full verification over the final subject; no changed core verifier or floors.
- [ ] Obtain one independent implementation review APPROVE on that exact subject with its worker
  idle and no tests/verifier running; resolve findings within bounds, reverify/re-review changes.
- [ ] Advisor issues ACCEPT_TASK; controller commits exactly the two implementation paths,
  scans the outgoing range and publishes non-force to origin/project-2-sqlite-registration-contract.

**Commit message.** `test(offline-data): verify golden dataset registration in temporary sqlite`

## 5. Acceptance and completion

The controller must issue VERIFY with verification_scope=full and verification_targets=[],
not infer full verification from the two test/doc paths. Run
offline_data/scripts/verify-offline.ps1, then the unchanged core scripts/verify.ps1 from this
worktree. Both must be PASSED on the same final subject/environment; all configured coverage,
schema, migration, build, distribution and hygiene checks remain in force. Earlier slice passes
and Workstream A's runs do not substitute for this subject's full gates.

At most two product implementation workers: Workstream A and this isolated worker.
One heavy verifier at a time under the shared host verifier lock (`.crypto-lab-host/verifier.lock`).
Keep P2 dispatch_wait_markers=[verify.ps1]; Workstream A takes priority when roots contend.
Do not edit or synchronize an execution surface while its worker or verifier is active.
After PASSED verification and independent APPROVE: ACCEPT_TASK, controller exact-manifest commit
and publication to the registered branch only. No Stage 9/main merge belongs to this task.
Record the completion token P2_SQLITE_REGISTRATION_CONTRACT_PLAN_COMPLETE only after the task
is accepted, committed and published. Report actual run/review/commit/publication identities.
New-plan commit/hash, its acceptance, new environments, runtime results and dispatch-time
resources are UNVERIFIED until recorded; this plan claims no production or real-data acceptance.
