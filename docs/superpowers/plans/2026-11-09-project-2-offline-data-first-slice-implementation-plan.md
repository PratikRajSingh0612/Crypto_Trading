# Project 2 - Offline historical candle data: first bounded slice (implementation plan)

> **For agentic workers.** This plan is the authority for the tasks it names. The
> approved specification (`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md`)
> and the reviewed core source outrank any paraphrase here. Where this plan declares a
> reading of the specification, the reading is listed in section 1.6 and the independent
> reviewer confirms or refutes it before acceptance. Nothing in this plan authorizes
> network access, real downloads, exchange credentials, live trading, cloud deployment,
> GitNexus activation or a dependency acquisition.

**Status.** Revision 10 (the Project 2 advisor decided BLOCKED for P2-T1 on 2026-11-09 at
21:01Z: sections 2.2 and 5.4 named no failure mechanism for an injected provider whose value
the core refuses, because no `Failure` can be built without a valid `Diagnostic`; this
revision adds declared reading R7 and the `ProviderContractError` mechanism in sections 1.6,
2.2, 2.5, 5.4 and the Task 1 and Task 3 interface lists, and changes nothing else; revision 9
history: round 8 REQUEST_CHANGES on sha256 `0c8b4650...`, revision 8: one
IMPORTANT, the tense of the authority-record clause, and four MINOR wording items folded in
here, every round-7 IMPORTANT confirmed closed; round 7 REQUEST_CHANGES on sha256 `09581069...`, revision 7: seven
IMPORTANT and five MINOR findings folded in here, the Task 0 design confirmed sound and
executable once fixed; revision 7 history: controller finding of 2026-11-09, 17:00Z: the worker's PreToolUse
hook admits a launcher only when it is committed at the task's base commit and admits no
lock or sync profile, so revision 6's Task 1 Step 0, in which the worker authored the
sub-project launcher and ran the offline proofs through it, was not executable by any
worker; this revision adds Task 0, a scaffold base commit authored by the controller
session and independently reviewed, moves the four environment proofs to the operator,
and leaves every worker task executable; an alternative is named under Task 0 for the
advisor's decision. Revision 6 history: round 5 REQUEST_CHANGES on `e2686a74...`: the
Task 1 boundary row, folded in here; independent review: round 1 REQUEST_CHANGES on sha256 `44174509...`,
round 2 APPROVE on `6804539e...`, re-pinned APPROVE on `b34034a4...`, round 4
REQUEST_CHANGES on `4ddc6b4f...` (P2-B2 bounding and the boundary-test RED row, folded in
here); advisor acceptance turn on `b34034a4...`: REJECTED with four binding conditions,
folded into revision 4): for advisor acceptance and independent re-review (owner authorization
"TWO PARALLEL PRODUCT WORKSTREAMS", 2026-11-09, section 3). Not accepted.

**Planning base.** Repository `Crypto_Trading`, branch `project-2-offline-data-plan`
created from accepted `main` at commit `079395bec70f1deda406d0ca14b2d4bf79aaf063`.
The implementation branch `project-2-offline-data-implementation` was created from the
same commit and is fast-forwarded to this plan's accepted revision commit before Task 0;
Task 0 is its first commit on top of the plan commit, so the mission gate's `plan_commit`
(this revision) is an ancestor of its `base_commit` (Task 0); the controller's gate check
requires the plan commit to be known and the base commit to be HEAD or an ancestor of it,
which this satisfies.

**Prerequisites.** Project 1 Stages 1-8 accepted and merged (`main` 079395be). Stage 9
is in progress on `project-1-stage-9-implementation` and is NOT a prerequisite of this
slice; the dataset contracts this slice consumes are byte-identical on `main` and on the
Stage 9 branch (section 2.2 pins their blob identities). Slice 3 (finalization through
the artifact finalizer) waits for the Stage 9 milestone merge and is a named forward
obligation, not a task of this plan.

**Goal.** Read one local historical-candle fixture in one documented input format,
validate and normalize it under the core's dataset rules, and emit the dataset metadata
the core already defines (`DatasetDescriptor`, `DatasetPartition`) with a deterministic
content identity, deterministic tests, valid and invalid fixtures, and no change to the
core package, its lockfile or its guards.

**Architecture.** A self-contained sub-project `offline_data/` inside the repository with
its own `pyproject.toml`, `uv.lock`, managed-Python environment and launcher, consuming
the core distribution `crypto-trading-lab` as a path dependency of its own environment.
It never writes into the core's environment. The placement rests on the owner's
authorization ("keep this component outside the core's dependency/runtime boundary")
and on the mission package's instruction to continue the existing repository
(`01_MISSION_AND_AUTHORITY.md:5`); the specification's isolated-runtime pattern
(sections 6.2 and 31.1) concerns engines and vendor clients and is cited as precedent
only.

**Tech stack.** Managed CPython 3.12 selected by `uv` (same interpreter family as the
core), standard library only for parsing and normalization (`csv`, `decimal`,
`datetime`, `hashlib`, `json`), the core package for the dataset models, hashing
profile, canonical JSON, decimal formatting, instrument parsing and UTC helpers. No
pandas, pyarrow, polars or numpy.

**Spec.** Specification sections 8.2 and 18.1-18.3 (datasets), 27.1 (`datasets`
placement), 32 (Project 2 boundary); roadmap `03_PRODUCT_ROADMAP.md:29-37` (P2 scope and
acceptance); `01_MISSION_AND_AUTHORITY.md:5, 26, 33`.

## Global Constraints

- **Core untouched.** No file under `src/crypto_lab/`, `tests/`, `schemas/`, `scripts/`,
  `pyproject.toml`, `uv.lock`, `.gitignore`, `AGENTS.md` or `CLAUDE.md` changes in this
  plan. The core's runtime dependencies stay exactly the four entries; the prohibited
  dependency families stay prohibited; the core's import-root, deferred-name and
  source-file censuses are not edited. A need to change any core file is a plan
  escalation to Workstream A, never a Project 2 edit.
- **Offline.** No network access, no real downloads, no exchange credentials, no cloud or
  server deployment, no GitNexus. Ordinary development and verification of the
  sub-project run with `--offline` managed-uv profiles exactly as the core's do.
- **Dependency acquisition.** None in this plan. The sub-project's own lockfile pins the
  complete closure to the exact versions the root `uv.lock` already carries (section
  2.7), so `uv lock --offline` resolves from the local cache the core populated. If the
  offline resolution fails, the exact missing distribution is reported once as
  acquisition boundary P2-B2; nothing is acquired. P2-B2 stops Task 0: the scaffold is not
  committed, no worker is dispatched (the mission gate's base commit does not exist yet)
  and no product code is authored, because no executable route other than the launcher's
  pinned `offline_data/.venv` exists (no `uv run`, no system Python, no provisional runner)
  and nothing is faked. The owner's clause to continue independently useful parsing and
  validation work then needs the owner's direction on its form (an authoring-only worker
  dispatch on the plan commit, prompt-bound to no execution since the core launcher stays
  admitted there, or waiting for the resolution); the
  one-time boundary report names that choice and the exact uv message. Workstream A is
  unaffected. No provisional type, refusal record or substitute of any core contract is
  created in any case.
- **Parquet boundary (P2-B1).** The specification makes dataset partitions Parquet files
  (specification lines 384, 1309). Parquet emission needs `pyarrow`, which is a prohibited
  family in the core and not approved for acquisition anywhere. This slice emits the
  validated normalized row stream, its checksums and the full metadata; the partition
  container is an explicitly labelled interim container (section 5.3). It is never
  presented as the production partition format: no file name, code path, document or
  descriptor field calls it a Parquet partition, every descriptor carries the limitation
  in `known_limitations`, every partition carries it in `quality_observations`, and no
  interim container enters any persistent registry (section 9). Lifting P2-B1 is a
  separately authorized acquisition and a later task.
- **Raw data outside Git.** Fixtures are small deterministic non-secret inputs under
  `offline_data/tests/fixtures/` (specification line 1946 convention). Outputs land only
  in caller-chosen output directories or test temporary directories; nothing under the
  repository root is written at run time; the forbidden root directories
  (`tests/safety/test_forbidden_runtime_paths.py`) stay absent.
- **Determinism.** Identifiers (`ds_`, `part_`, `diag_`) and timestamps
  (`created_at_utc`, `imported_at_utc`, diagnostic `timestamp_utc`) come from injected
  providers (section 5.4); tests inject fixed values. The content hash excludes
  identifiers and creation and import times by the core's own hashing profile, so the
  golden hash of a fixture is stable across runs and machines.
- **Decimal and UTC.** Prices and volumes are `decimal.Decimal` from the exact source
  text; no float is ever constructed. Timestamps are timezone-aware UTC; naive values and
  non-UTC offsets are refused, never converted.
- **No silent fabrication.** Missing bars and duplicate bars are explicit records in the
  descriptor; rows are never interpolated, dropped silently or de-duplicated silently.
- **Test-first.** Every behaviour lands as a focused failing test, the minimum
  implementation, the focused passing test, then the sub-project's quality gates.
- **Execution route.** The worker reaches the sub-project's tooling only through the
  committed `offline_data/scripts/invoke-offline-uv.ps1`. Two named prerequisites make that
  true; both are recorded in the Project 2 controller root's `config/mission_checkpoint.md`
  before the first dispatch, and neither is a property any committed controller has at the
  time of this revision: (1) the controller release that binds a policy-named second
  committed launcher for the worker's per-run hook (its commit hash is recorded when it
  lands); (2) the Project 2 root's reviewed policy values `checkpoint_launcher =
  offline_data/scripts/invoke-offline-uv.ps1`, `checkpoint_profiles = [ruff-format-all,
  ruff-check-all, mypy-all]`, and the protected paths `offline_data/.venv/`,
  `offline_data/scripts/`, `offline_data/pyproject.toml` and `offline_data/uv.lock`, so no
  worker can edit the environment or its definition (no worker task of this plan modifies
  any of them). With both in place the hook admits the committed launcher for
  `pytest-focused`, `ruff-format-all`, `ruff-check-all` and `mypy-all` only. The environment
  profiles `lock-resolve-offline`, `lock-check` and `sync` are operator-run (the controller
  session), never a worker's, exactly as in the core; `verify-offline.ps1` for worker tasks
  is run by the controller through its `full_verification_commands`, never by the worker.
  The hook binds a launcher to its bytes at the task's base commit, so a launcher that is
  not committed there cannot be run by the worker; this is why Task 0 exists.

## 1. Goal, scope and exclusions

### 1.1 Goal

A deterministic offline pipeline `fixture -> validated rows -> normalized container +
checksums -> DatasetDescriptor + DatasetPartition metadata` for one input format and one
representative instrument, proven against the core's own models, hashing profile and
JSON schemas, inside an isolated sub-project environment.

### 1.2 In scope

| Area | Delivers | Owning task |
|---|---|---|
| Sub-project scaffold | `offline_data/` with pyproject, pinned lock, launcher, verify script, README | Task 0 (scaffold base commit) |
| Input contract `ohlcv-csv/1` | Strict reader: header, row grammar, Decimal and UTC parsing, bounded size, injected diagnostics | Task 1 |
| Validation | Ordering, duplicates, missing bars, invalid prices and volumes, timeframe grid, canonical decimal form, timezone | Task 2 |
| Normalization | Canonical normalized rows, raw and normalized checksums, half-open interval | Task 2 |
| Metadata emission | `DatasetPartition`, `DatasetDescriptor`, `dataset_metadata_hash`, identity validation, canonical JSON files | Task 3 |
| Command entry | `python -m crypto_lab_offline_data normalize ...` writing to an output directory | Task 3 |
| Fixtures and goldens | One clean valid fixture, one valid-with-warnings fixture, eleven invalid fixtures, golden descriptor, partitions and hash | Tasks 1-3 |

### 1.3 Out of scope

| Excluded | Reason | Owner |
|---|---|---|
| Real source verification (Binance archive layout, timestamp units, checksums, licensing) | Needs network; roadmap P2 first deliverable, separately authorized | later P2 task after authorization |
| Any download, acquisition or bounded smoke run | Not authorized | later P2 task after authorization |
| Parquet partition emission | P2-B1 (pyarrow prohibited, not acquired) | later P2 task after authorization |
| Registration into a persistent core dataset registry | Interim containers never enter a persistent registry; slice 2 is a temporary-database contract test | Workstream A forward obligation |
| Finalization through the artifact finalizer (`DATASET` owner) | Slice 3; needs the Stage 9 milestone merge | Workstream A forward obligation |
| Multiple input formats, multiple instruments, multi-partition datasets | Second slice | later P2 task |
| Changes to shared contracts (models, schemas, hashing profile, a core `datasets/validation.py`) | Belong to Workstream A with consumer tests (specification 27.1 places shared partition validation contracts in the core `datasets` package; none exists today) | Workstream A |
| Dashboard, engines, VectorBT research | Not this workstream | - |

### 1.4 Named forward obligations

1. **Slice 2 (Workstream A):** a core-side contract test, against a temporary SQLite
   database only, registering a descriptor and partitions emitted by this slice through
   `SqliteDatasetRepository.register` and reading them back by `content_hash` and
   `ordinal`. Input: the golden files this plan commits under
   `offline_data/tests/fixtures/candles/golden/`. Not a production registration: interim
   containers stay out of any persistent registry until P2-B1 is lifted.
2. **Slice 3 (Workstream A, after the Stage 9 merge):** finalization of a normalized
   container as a `DATASET_INPUT`/`DATASET` artifact with the `DatasetArtifactOwner`.
3. **P2-B1 lift:** Parquet emission once `pyarrow` is an approved acquisition in the
   sub-project environment only; the interim container is then retired.
4. **Source verification:** the roadmap's first deliverable (official schema, timestamp
   units, archive checksums, licensing) and the real-format adapter it enables.
5. **Shared validation contract (Workstream A):** specification 27.1 names partition
   validation contracts in the core `datasets` package; this slice's rule set is
   importer-side and does not define that contract.

### 1.5 Carried notes

- The core's `Bar` evaluation model (`strategy/evaluation.py`) is not a dataset row
  contract and is not consumed; the normalized row schema of this slice is declared in
  section 5.2 and versioned by `column_schema_version`.
- The specification promises Parquet schema declarations under `schemas/artifacts`; none
  exist. This slice does not create them (shared-contract territory).
- Partition `content_hash` and `normalized_checksum` are both the SHA-256 of the one
  container's bytes in this slice and are therefore equal by construction; the two
  fields diverge only when a partition container differs from the normalized stream
  (for example a future Parquet encoding of the same rows).

### 1.6 Escalations and declared readings the reviewer must confirm

- **R1 Placement.** A sub-project `offline_data/` inside the repository with its own
  environment is the correct reading of the owner's "outside the core's
  dependency/runtime boundary" together with `01_MISSION_AND_AUTHORITY.md:5` ("Continue
  the existing Crypto_Trading repository") and the controller policy (no new publication
  remotes). Alternatives refused: a separate repository (new remote) or a package inside
  `src/crypto_lab` (prohibited families and guard edits). The specification's sections
  6.2 and 31.1 are precedent for isolated environments, not a statement about this
  sub-project.
- **R2 Input format.** A documented versioned CSV format `ohlcv-csv/1` (section 3) is the
  "one supported input format" for this slice. The Binance archive layout is NOT asserted
  from memory (roadmap `:31`); its adapter follows the authorized source verification.
- **R3 Interim container.** Emitting a canonical NDJSON normalized container labelled
  `normalized-ndjson/0.1.0` does not "fake the required production output format"
  because: nothing names it a Parquet partition (specification `:384`, `:1309` are the
  production requirement and are cited as unmet in the README); every descriptor
  carries the P2-B1 text in `known_limitations` and every partition in
  `quality_observations`; and no interim container enters a persistent registry.
- **R4 Validation status (corrected in revision 2).** By `models.py:411-417` a
  `VALID_WITH_WARNINGS` descriptor requires a quality fact, and the only quality facts
  are `missing_intervals`, `duplicate_intervals` or `diagnostic_ids`; `known_limitations`
  and partition `quality_observations` are not quality facts and are allowed on a
  `VALID` descriptor. Therefore: the clean fixture is `VALID` (carrying the P2-B1
  limitation and partition observation); a fixture with gaps or duplicates is
  `VALID_WITH_WARNINGS` with interval records; any refused row makes the whole input a
  `Failure` and no descriptor, partition or container is written (`INVALID` is never
  emitted by this slice).
- **R5 Half-open interval.** `start_utc` is the first bar's open time and `end_utc` is
  the last bar's open time plus one timeframe step (`models.py:91-101`, specification
  `:1293`); a gap is a `TimeInterval` from the first missing open time to the next
  present open time; a duplicate is a `DuplicateInterval` over one step with
  `duplicate_count >= 2`.
- **R6 Core consumption.** Consuming `crypto-trading-lab` as a path dependency inside the
  sub-project's own environment keeps the core's lockfile and environment untouched and
  is the intended way to "use the existing contracts rather than inventing a parallel
  data model". Task 0 proves that the `[tool.uv.sources]` path source is honoured under
  the launcher's `--no-config` controls (section 2.7); if it is not, Task 0 stops as
  P2-B2 with the exact uv message.
- **R7 Provider faults are composition faults.** An injected `IdProvider` or `Clock` that
  yields a malformed prefixed identifier or a naive or non-UTC instant is a fault of the
  caller's composition, not of the input: the core's `Diagnostic` cannot be built from it
  (`diagnostic_id` and `timestamp_utc` are validated by the core), so no `Failure` exists to
  return. The sub-project validates each provider value where it is consumed and raises
  `ProviderContractError`, a sub-project exception deriving from `ValueError`, defined in
  `diagnostics.py`, naming the provider method and never carrying the value, from the
  public functions `refusal` and `read_ohlcv_csv` (Task 1) and `build_dataset_metadata` and
  `normalize_command` (Task 3; the command maps it to exit code 3 and writes no output). It is
  the only exception that crosses the sub-project's public boundary; tests pin it with
  `pytest.raises(ProviderContractError)` and pin that the core `ValidationError` does not
  escape. This replaces the earlier declared reading that the core `ValidationError`
  propagates.

## 2. Authority, consumed interfaces, readings and reconciliation

### 2.1 Authority order

Specification; reviewed core source at the pinned blobs; this plan; the sub-project's
README. Advisor and reviewer output is advisory and cannot override the first three.

### 2.2 Consumed interfaces (pinned at `main` 079395be; identical on the Stage 9 branch)

<!-- consumed -->
| Symbol | Module (blob) | Contract |
|---|---|---|
| `DatasetDescriptor`, `DatasetPartition`, `TimeInterval`, `DuplicateInterval`, `RawSourceProvenance`, `DatasetDataType`, `DatasetValidationStatus` | `src/crypto_lab/datasets/models.py` (`9c5c5b99`) | Strict frozen canonical models; `extra=forbid`; unique sorted intervals; `VALID` forbids missing and duplicate intervals and diagnostic ids; `VALID_WITH_WARNINGS` requires one of them; a zero-row partition needs an observation; OHLCV requires `timeframe`; venue equals instrument venue; `content_hash` is a required field |
| `dataset_metadata_hash`, `validate_dataset_identity` | `src/crypto_lab/datasets/hashing.py` (`bb5f05f7`) | SHA-256 over the canonical hash envelope `{schema_version, hashing_profile, payload}`; excludes descriptor `content_hash`, `created_at_utc`, `dataset_id`, `diagnostic_ids`, `imported_at_utc`, `partition_ids` and partition `dataset_id`, `partition_id`, `relative_path`; partitions ordered by `partition_ids` with `ordinal == index`, bounds inside the descriptor, partition provenance a subset of the descriptor's, checksum tuples equal, `column_schema_version` equal |
| `HashingProfile.DATASET_METADATA_V1`, `CanonicalHashEnvelope` | `src/crypto_lab/domain/hashing.py` | profile literal `dataset-metadata/v1` |
| `DatasetRepository` | `src/crypto_lab/datasets/ports.py` (`f4d2f5a3`) | Read only here: documents the registration contract slice 2's temporary-database test will satisfy |
| `dataset-descriptor-v1`, `dataset-partition-v1` JSON schemas | `schemas/datasets/*.schema.json` (`d997ed79`, `7ea31efe`) | Emitted JSON must re-validate through the core models in strict JSON mode |
| `InstrumentRef`, `parse_instrument_id`, `MarketType` | `src/crypto_lab/domain/records.py`; `AssetCode` in `domain/identifiers.py` | `canonical_id == VENUE:BASE/QUOTE:MARKET`; the command's `--instrument` is parsed by the core helper, not re-implemented |
| `UtcDateTime`, `require_utc`, `format_utc` | `src/crypto_lab/domain/time.py` | Timezone-aware UTC only; JSON form `YYYY-MM-DDTHH:MM:SS(.ffffff)?Z` |
| `CanonicalDecimal`, `PositiveDecimal`, `NonNegativeDecimal`, `format_decimal` | `src/crypto_lab/domain/financial.py` | Python `Decimal` input; canonical finite string in JSON (`format_decimal` strips trailing zeros; the canonical grammar rejects `.5`, `5.`, `007`); no float |
| `canonical_json_bytes` | `src/crypto_lab/domain/canonical_json.py` | Sorted keys, compact separators, UTF-8, `ensure_ascii=False`, float forbidden |
| `Success`, `Failure`, `Diagnostic`, `DiagnosticSeverity`, `DiagnosticCategory` | `src/crypto_lab/domain/results.py`, `domain/diagnostics.py` | `Failure.diagnostics` has at least one `Diagnostic`; a `Diagnostic` requires `diagnostic_id` (`diag_` UUID4), `severity`, `error_code` (`^[A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)+$`), `category`, `message`, `source_component`, `retriable`, `timestamp_utc`, `details`, `causal_diagnostic_ids` |
| `validate_prefixed_uuid4`, `DatasetId`, `DatasetPartitionId`, `DiagnosticId` | `src/crypto_lab/domain/identifiers.py` | format checks for injected identifiers; the core mints none of these three prefixes itself |

The implementer re-reads each consumed module before use and refuses to proceed if a
blob differs from the pinned identity (report the drift; do not adapt silently). Core
`ValueError` and Pydantic `ValidationError` raised for data-dependent values (anything
derived from the input) are caught at the sub-project boundary and converted to
`Failure`; no such exception crosses the sub-project's public functions. The one
deliberate exception is a composition fault: an injected provider value the core refuses
makes a `Failure` unconstructible, so it is raised as the sub-project's
`ProviderContractError` (reading R7, section 1.6), never converted and never surfaced as a
bare core exception.

### 2.3 Placement decisions

- Package name `crypto_lab_offline_data`, distribution name `crypto-lab-offline-data`,
  version `0.1.0`, under `offline_data/src/`, `requires-python = ">=3.12,<3.13"`.
- `offline_data/pyproject.toml` carries its own `[tool.ruff]` (`src = ["src", "tests"]`,
  the core's select set, `line-ending = "lf"`, per-file `S101` for `tests/**/*.py`),
  `[tool.mypy]` (strict, `files = ["src", "tests"]`), `[tool.pytest.ini_options]`
  (`testpaths = ["tests"]`, branch coverage on `crypto_lab_offline_data`,
  `--cov-fail-under=98.61`, the sub-project's one configured floor, see the verify-script
  bullet below) and `[tool.coverage]`.
  The core's `ruff-check-all` (`ruff check .` from the repository root) and
  `ruff-format-all` (`ruff format --check .`) traverse `offline_data/` and apply this nested
  configuration by hierarchical discovery; those stages of the core's `verify.ps1` must
  stay green over the sub-project, and the repository's completion rule (`AGENTS.md`: run
  `scripts/verify.ps1` before claiming completion) applies to every Project 2 task.
- The sub-project's own `scripts/invoke-offline-uv.ps1` mirrors the core launcher's
  closed profile set (`lock-check`, `lock-resolve-offline`, `sync`, `pytest-focused`,
  `ruff-format-all`, `ruff-check-all`, `mypy-all`, plus `pytest-all` for the verify script
  alone, never admitted to a worker) with the same `--offline`,
  `--managed-python`, `--no-python-downloads`, `--no-config` controls, rooted at
  `offline_data/` (its `pytest-focused` takes targets under `offline_data/tests/`,
  spelled `tests/...` relative to that root) and pinned to `offline_data/.venv`. Its
  distinct file name matters for the controller's competition rule only across
  worktrees; inside one worktree every launcher run is competition, which is why section
  8 runs verification alone. The launcher and the verify script are committed by Task 0
  before any worker dispatch, because the controller's hook binds a launcher to its bytes
  at the base commit and admits no environment profile.
- `offline_data/scripts/verify-offline.ps1` runs: lock check, sync, format check, lint,
  strict types, test suite with branch coverage (`pytest-all`), Git whitespace check. The
  branch coverage floor is 98.61 percent, enforced by `--cov-fail-under=98.61` in the
  sub-project's own pytest addopts in `offline_data/pyproject.toml` (the figure the current
  core stage plan holds as its acceptance requirement; the core's configured floor of 90
  percent is the core's own setting and is not re-stated here), so no weaker testing policy
  is introduced; `pytest-all` takes no arguments. For worker tasks the verify script is run
  by the controller through its `full_verification_commands`, never by the worker (the
  hook admits no profile that runs lock check or sync).
- `offline_data/.venv` is ignored by the root `.gitignore` pattern `.venv/` without
  editing that protected file. `offline_data/uv.lock` is committed.

### 2.4 Frozen-byte and contract constraints

The core distribution is consumed exactly as built from the repository root
(`[tool.uv.sources] crypto-trading-lab = { path = "../" }`, non-editable). Building that
wheel under the mirrored `sync --no-build-isolation` requires `hatchling==1.31.0` (and
its closure) in the sub-project's dev group, as the core itself carries. No core module
is monkeypatched, subclassed with overridden validators, or re-implemented;
`model_copy(update=...)` is never used on core models because it bypasses validators.

### 2.5 Declared readings of the specification

R1-R7 in section 1.6. The reviewer confirms each against the quoted lines before
acceptance; a refuted reading stops the task that depends on it.

### 2.6 Closed-world guard reconciliation

**Core guards: no transition.** No path under `src/crypto_lab`, `tests`, `schemas` or
`scripts` changes, so the Stage 3-9 censuses (source files, import roots, deferred
names) are untouched and need no reconciliation table. Core stages that reach the
sub-project: `ruff-format-all` and `ruff-check-all` (section 2.3). Core stages that do not: `mypy-all`
(`files = src, tests, scripts`), `pytest` (`testpaths = tests`), coverage
(`source = crypto_lab`), hatch sdist and wheel (explicit lists), schema distribution and
generation (`schemas/` only), the stage censuses (rooted at `src/crypto_lab`, `tests`,
`scripts`, `schemas`), and `test_forbidden_runtime_paths.py` (first path segment only;
`offline_data/.venv` is not forbidden and is git-ignored).

**Sub-project guards (created by Task 1):** `offline_data/tests/safety/test_boundaries.py`
pins the sub-project's runtime dependency list to exactly `crypto-trading-lab` (path
source) and nothing else; pins the dev group to the exact set of section 2.7; forbids
`pandas`, `pyarrow`, `polars`, `numpy`, `requests`, `httpx` and the other prohibited
families by name in the sub-project lock; forbids any `socket`, `urllib`, `http`,
`subprocess` or `os.environ` import in `crypto_lab_offline_data`; asserts the lock
records `crypto-trading-lab` with a `directory = "../"` source; asserts every package
version recorded in `offline_data/uv.lock` equals the section 2.7 list (so the
`constraint-dependencies` under `[tool.uv]` are proven honoured, like the path source);
and asserts the reader writes nothing. The command's `--output` confinement is asserted
in Task 3's `tests/unit/test_cli.py` (Task 3 Step 1, the `--output` handling of section 6).

### 2.7 Toolchain gates and the exact pinned closure

Managed CPython 3.12 via `uv python find --managed-python --system --no-python-downloads 3.12`
(same prerequisite as the core). The sub-project pins its entire closure with `==` to the
versions the root `uv.lock` already resolved, so `lock-resolve-offline` and `lock-check`
work from the local cache:

- runtime: `crypto-trading-lab` (path) and, transitively, `pydantic==2.13.4`,
  `pydantic-core==2.46.4`, `typing-extensions==4.16.0`, `typing-inspection==0.4.4`,
  `annotated-types==0.8.0`, `sqlalchemy==2.0.54`, `greenlet==3.5.6`, `alembic==1.20.0`,
  `mako==1.4.1`, `markupsafe==3.0.3`, `pyyaml==6.0.3` (declared as uv
  `constraint-dependencies` so the resolver cannot pick newer cached index entries);
- dev: `pytest==8.4.2`, `pluggy==1.6.0`, `iniconfig==2.3.0`, `packaging==26.3`,
  `colorama==0.4.6`, `pygments==2.20.0`, `pytest-cov==6.3.0`, `coverage==7.15.4`,
  `ruff==0.16.2`, `mypy==1.20.2`, `mypy-extensions==1.1.0`, `pathspec==1.1.1`,
  `librt==0.15.0`, `hatchling==1.31.0`, `trove-classifiers==2026.6.1.19` (the sub-project
  imports no yaml, so `types-pyyaml` is not carried).

Task 0 proves, in this order and offline, run by the controller session through the
sub-project launcher as authored (the bytes Task 0 commits): `lock-resolve-offline` succeeds (this proof produces
`offline_data/uv.lock`, committed in Task 0); `lock-check` passes; `offline_data/uv.lock`
records `crypto-trading-lab` with a `directory = "../"` source; `sync` builds the core wheel
without isolation. Any failure is reported once with the exact uv message as P2-B2; Task 0
is then not committed, nothing is dispatched or authored, and the boundary report asks the
owner how the continuation clause is to be honoured (Global Constraints). No worker runs an
environment profile.

### 2.8 Dependency acquisition gates

None. P2-B1 (pyarrow) and P2-B2 (any distribution the offline lock cannot resolve) are
reporting boundaries, not acquisitions.

## 3. Input contract `ohlcv-csv/1`

- UTF-8 text, LF or CRLF line endings, first line exactly
  `open_time_utc,open,high,low,close,volume`.
- Each data row has exactly six fields. `open_time_utc` is `YYYY-MM-DDTHH:MM:SSZ`
  (seconds precision, literal `Z`); any other form, including naive values and numeric
  offsets, is refused. `open`, `high`, `low`, `close` and `volume` match
  `[0-9]+(\.[0-9]+)?` (no exponent, no sign, no leading `+`, no bare `.5` or `5.`);
  prices must be positive and `volume` non-negative after parsing. The canonical
  normalized form is `format_decimal` of the parsed `Decimal` (trailing zeros stripped,
  `1.50` -> `1.5`); the raw text's exact digits survive only through `raw_checksum`.
- Size ceilings: at most 1,048,576 rows and 64 MiB per input; exceeding either is a
  refusal, never a truncation.
- Empty file, header-only file, wrong header, wrong field count, blank line inside the
  body, non-UTF-8 bytes: refused with a diagnostic naming the one-based line number and
  the rule, never the offending value (only its length and position are recorded). A
  header-only file is the reader's `OFFLINE_DATA.EMPTY_SERIES` refusal, the same code
  `validate_series` returns for an empty row tuple, so Task 1 and Task 2 pin one answer.
- Identity of the raw input: `raw_checksum` is SHA-256 of the exact input bytes.

## 4. Validation and normalization rules

| Rule | Behaviour | Descriptor effect |
|---|---|---|
| Ordering | Rows must be non-decreasing in `open_time_utc`; a decrease is a refusal | `Failure`, nothing written |
| Duplicates | Equal `open_time_utc` on consecutive rows: all rows kept in the normalized container; a `DuplicateInterval(start=open_time, end=open_time + step, duplicate_count=n)` recorded; rows with equal time but differing values additionally raise a partition quality observation | `duplicate_intervals`; status `VALID_WITH_WARNINGS` |
| Timeframe grid | Every `open_time_utc` must sit on the timeframe grid (`open_time % step == 0` from the Unix epoch); off-grid is a refusal | `Failure` |
| Missing bars | A gap of `k >= 1` steps between consecutive distinct open times records `TimeInterval(start=first missing open, end=next present open)`; never filled | `missing_intervals`; status `VALID_WITH_WARNINGS` |
| Price sanity | `low <= open, close <= high`, all prices positive; violation is a refusal | `Failure` |
| Volume | non-negative; violation is a refusal | `Failure` |
| Decimal form | Values parsed exactly; normalized with `format_decimal`; raw digits preserved only via `raw_checksum` | `normalized_checksum` |
| Timezone | Only `Z`; naive or offset values are refusals | `Failure` |
| Interval | `start_utc = first open`, `end_utc = last open + step` (half-open) | `start_utc`, `end_utc` |
| Row count | `row_count` = number of rows written to the container, duplicates included, so an independent line count agrees with the metadata (specification `:553`, `:1309`; roadmap `:35`); the distinct count follows from `duplicate_intervals` | `row_count` |
| Empty series | zero data rows is a refusal for this slice | `Failure` |
| No refusal, no gap, no duplicate | the clean case | status `VALID` (R4) |

Timeframe grammar is the core's `Timeframe` pattern `^[1-9][0-9]*(?:s|m|h|d|w)$`; this
slice supports `1m`, `5m`, `15m`, `1h`, `4h`, `1d` and refuses other values with a
diagnostic (second and week steps are out of scope for this slice).

## 5. Metadata emission

### 5.1 Descriptor and partition mapping

Descriptor:

| Field | Source |
|---|---|
| `schema_version` | `"1.0.0"` |
| `dataset_id` | injected id provider (`ds_<uuid4>`) |
| `source` | command argument `--source` (bounded text), default `local-fixture` |
| `venue`, `instrument` | `parse_instrument_id(--instrument)` (`VENUE:BASE/QUOTE:MARKET`) |
| `data_type` | `OHLCV` |
| `timeframe` | `--timeframe` |
| `start_utc`, `end_utc` | section 4 |
| `original_timezone` | `"UTC"` (the input contract admits only `Z`) |
| `normalized_to_utc` | `True` |
| `imported_at_utc`, `created_at_utc` | injected clock |
| `raw_source_provenance` | one entry: `source_name = "ohlcv-csv"`, `source_version = "1.0.0"`, `source_record = <input file name, bounded>`, `source_hash = raw_checksum` |
| `normalization_implementation` | `"crypto-lab-offline-data"` |
| `normalization_version` | the sub-project version `0.1.0` |
| `validation_status` | section 1.6 R4 |
| `partition_ids` | the one partition id |
| `missing_intervals`, `duplicate_intervals` | section 4 (sorted, unique) |
| `diagnostic_ids` | empty (a refused input emits no descriptor) |
| `raw_checksums`, `normalized_checksums` | one entry each, partition order |
| `column_schema_version` | `"0.1.0"` (section 5.2) |
| `known_limitations` | exactly one entry in this slice: `"interim container normalized-ndjson/0.1.0; Parquet partition emission requires the pyarrow acquisition (P2-B1)"` (sorted when more are added) |
| `content_hash` | section 5.4 construction |

Partition (one, `ordinal = 0`):

| Field | Source |
|---|---|
| `schema_version` | `"1.0.0"` |
| `partition_id` | injected id provider (`part_<uuid4>`) |
| `dataset_id` | the descriptor's |
| `ordinal` | `0` |
| `relative_path` | `datasets/<dataset_id>/part-0000.ndjson` (registry-relative POSIX; accepted by `RegistryRelativePath`) |
| `content_hash` | SHA-256 of the container bytes |
| `row_count` | section 4 (container rows) |
| `start_utc`, `end_utc` | the descriptor's |
| `raw_checksum` | SHA-256 of the raw input bytes |
| `normalized_checksum` | SHA-256 of the container bytes (equal to `content_hash` here, section 1.5) |
| `column_schema_version` | `"0.1.0"` |
| `raw_source_provenance` | the descriptor's single entry (subset rule of `hashing.py`) |
| `quality_observations` | the P2-B1 observation, plus the differing-duplicate observation when raised (sorted, unique) |

### 5.2 Normalized row schema `0.1.0`

One JSON object per line, keys in this order after canonicalization:
`close`, `high`, `low`, `open`, `open_time_utc`, `volume`; numeric fields are
`format_decimal` strings; `open_time_utc` is the core UTC string form. Lines end with
`\n`; the file ends with a final newline; `normalized_checksum` is SHA-256 of the whole
container.

### 5.3 Interim container

The container is written as `part-0000.ndjson` under the caller's output directory next
to `descriptor.json` and `partitions.json` (canonical JSON of the models). The README and
every descriptor and partition name it as interim (P2-B1). No code path, file name or
documentation calls it a Parquet partition, and it never enters a persistent registry.

### 5.4 Identity, clock and content-hash construction

- `IdProvider` protocol (sub-project): `dataset_id() -> str`, `partition_id() -> str`,
  `diagnostic_id() -> str`, each validated with the core's `validate_prefixed_uuid4`
  against its prefix (a refused value raises `ProviderContractError`, R7); the production
  provider mints UUID4; tests inject fixed values.
- `Clock` protocol (sub-project): `now_utc() -> datetime` (timezone-aware UTC; a naive or
  non-UTC instant raises `ProviderContractError`, R7); tests inject a fixed instant.
- Diagnostics: `error_code` from the closed set `OFFLINE_DATA.CSV_ENCODING`,
  `OFFLINE_DATA.CSV_HEADER`, `OFFLINE_DATA.CSV_ROW_SHAPE`, `OFFLINE_DATA.CSV_TIMESTAMP`,
  `OFFLINE_DATA.CSV_NUMBER`, `OFFLINE_DATA.SIZE_CEILING`, `OFFLINE_DATA.ORDERING`,
  `OFFLINE_DATA.TIMEFRAME_GRID`, `OFFLINE_DATA.PRICE_SANITY`, `OFFLINE_DATA.VOLUME`,
  `OFFLINE_DATA.EMPTY_SERIES`, `OFFLINE_DATA.OUTPUT_DIRECTORY`; `severity = ERROR`;
  `category` `SCHEMA_VALIDATION`; `source_component = "crypto-lab-offline-data"`;
  `retriable = False`; `message` names the line and rule only; `details` carries
  `{"line": n, "rule": code, "value_length": k}`; `timestamp_utc` from the injected clock.
- Content hash: build the descriptor with `content_hash = "0" * 64`, compute
  `dataset_metadata_hash(descriptor, partitions)` (the placeholder is excluded by the
  profile), re-create the descriptor through
  `DatasetDescriptor.model_validate({**descriptor.model_dump(), "content_hash": h})`,
  then call `validate_dataset_identity`. Never `model_copy(update=...)`.

## 6. Test strategy, fixtures and goldens

Fixtures under `offline_data/tests/fixtures/candles/`:

- `btcusdt-1m-clean.valid.csv`: 60 consecutive 1m bars, `BINANCE:BTC/USDT:SPOT`
  (synthetic values; the instrument string exercises the canonical id grammar, not a
  claim about real market data).
- `btcusdt-1m-gaps-duplicates.valid.csv`: 60 bars with one 3-bar gap, one duplicated
  open time (identical values) and one duplicated open time (differing values).
- `invalid/` (eleven files): `naive-timestamp.csv`, `offset-timestamp.csv`,
  `float-exponent.csv`, `negative-price.csv`, `high-below-low.csv`, `unsorted.csv`,
  `off-grid.csv`, `wrong-header.csv`, `extra-column.csv`, `empty.csv`,
  `header-only.csv`.
- `golden/`: `btcusdt-1m-clean.descriptor.json`, `btcusdt-1m-clean.partitions.json`,
  `btcusdt-1m-clean.content_hash.txt`, and the same three for the gaps-duplicates fixture,
  produced with the fixed test ids and clock. Each golden is captured once from the
  first GREEN run of Task 3 and committed as a review oracle: no regeneration command,
  no update option. Independence comes from the consumer check (section 9.1), which
  recomputes the hash with the core's own function, not from the golden file itself.

Deterministic tests (`offline_data/tests/unit/`): reader grammar (one test per refusal,
asserting the diagnostic code, line and the absence of the value), rule matrix of
section 4 (one test per row, both valid fixtures), normalization bytes and checksums,
descriptor and partition construction, golden equality, identity validation, re-run
idempotency (same bytes, same hash), output-directory confinement (`--output` may be
absolute or relative; it is resolved, created when absent, must be a directory, reparse
points are refused, and nothing is written outside it), size ceilings, the boundary
tests of section 2.6. A consumer check re-parses the emitted JSON through the core
models in strict JSON mode and recomputes the hash with the core's function.

## 7. Task decomposition

Each worker task: test-first, one commit, clean worktree, `offline_data/scripts/verify-offline.ps1`
green and then the core's `scripts/verify.ps1` green (run alone, serialized by the
controller) before the commit. The sub-project never touches the core's paths.

### Scaffold base commit, called Task 0 (controller session; not a worker dispatch, so not a `### Task n` heading)

**Why a Task 0.** The controller's worker hook admits a launcher only when it is committed
at the task's base commit, and it admits no lock or sync profile: the environment is
operator-provisioned, exactly as for the core. A worker therefore cannot author the
sub-project launcher and run it within the same task. Task 0 is performed by the controller
session as the mission's base commit under the same delegated acceptance as this plan: a
hash-pinned independent review of the scaffold diff by a read-only reviewer, and the
advisor's acceptance of this revision, which names the scaffold's exact file list and
proofs, and a separate advisor acceptance turn on the Task 0 commit hash itself (Step 7).
It is recorded as a delegated acceptance, never as a human review. The owner
authorization's text will be recorded verbatim in the Project 2 controller root's
`config/mission_checkpoint.md` before the first dispatch, alongside the two
Execution-route prerequisites; this plan paraphrases it.

**Files created.** `offline_data/pyproject.toml` (section 2.3 configuration, section 2.7
pins), `offline_data/uv.lock` (produced by the first proof), `offline_data/README.md`
(scope, the operator-run environment profiles, the worker's admitted profiles, the two
reporting boundaries; the input format section is written by Task 1),
`offline_data/scripts/invoke-offline-uv.ps1`, `offline_data/scripts/verify-offline.ps1`,
`offline_data/src/crypto_lab_offline_data/__init__.py` (`__version__ = "0.1.0"` only),
`offline_data/tests/conftest.py` (the explicit test root; no fixtures yet),
`offline_data/tests/unit/test_package.py` (one smoke test pinning `__version__`, so the
verify script's test stage collects a test and the coverage floor is measured over the
one-line package). No production behaviour, no fixture, no reader.

**Files modified.** None.

**Steps.**

- [ ] **Step 1 Author.** The files above per sections 2.3 and 2.7: the launcher carries
  exactly eight profiles, a subset mirror of the core launcher's closed set (`lock-check`,
  `lock-resolve-offline`, `sync`, `pytest-focused`, `pytest-all`, `ruff-format-all`,
  `ruff-check-all`, `mypy-all`; `pytest-all` is the verify script's stage and is never
  admitted to a worker) and the core's controls (`--offline`, `--managed-python`,
  `--no-python-downloads`, `--no-config` on every uv invocation, exactly one resolvable
  `uv.exe`, absolute tools pinned in `offline_data/.venv`, no `uv run` outside the pinned
  environment, no caller-selected Python or flags, no network-capable profile), rooted at
  `offline_data/`, with `pytest-focused` targets spelled `tests/...` relative to that root;
  the verify script runs lock check, sync, format check, lint, strict types, `pytest-all`
  (branch coverage at the 98.61 percent floor configured in `pyproject.toml`), and the Git
  whitespace check, each through the launcher. LF line endings (as `.gitattributes`
  enforces); nothing outside `offline_data/` is written. Nothing is executed in this step.
- [ ] **Step 2 Pre-execution review.** Before any proof runs, a read-only reviewer reads the
  authored launcher, verify script and `pyproject.toml` bytes (hash-pinned) and confirms:
  every uv invocation carries `--offline --no-config --managed-python --no-python-downloads`;
  the profile set is exactly the eight above; no `uv run`, no dot-sourcing, no network-capable
  profile, no caller-selected interpreter; the pins equal section 2.7. A finding stops Task 0
  before execution.
- [ ] **Step 3 Proofs (operator).** The four ordered offline proofs of section 2.7 through
  the reviewed launcher (the exact bytes Step 6 commits); on any failure, P2-B2 is reported
  once and Task 0 is not committed.
- [ ] **Step 4 Gates (operator).** `verify-offline.ps1` green; the core `scripts/verify.ps1`
  green (run alone on the host).
- [ ] **Step 5 Full-diff review.** Independent hash-pinned review of the whole scaffold diff
  (now including `offline_data/uv.lock`) by a read-only reviewer: launcher closure,
  verify-script stage list, pin equality with section 2.7, the lock's `directory = "../"`
  source record and its version equality with the root lock, a token-shape scan over every
  file including `README.md` and `uv.lock` (no credential shape; no URL outside the lock's
  `registry` and distribution `url` fields), no core path touched, no network, no
  acquisition.
- [ ] **Step 6 Commit.** `chore(offline-data): scaffold the isolated sub-project environment
  and launcher` on `project-2-offline-data-implementation`, authored by the controller
  session, after the controller's own outgoing token-shape scan. The mission gate pins this
  commit as `base_commit` and this revision's commit as `plan_commit`; the controller
  binds the committed launcher for every later worker dispatch.
- [ ] **Step 7 Advisor acceptance of the commit.** A read-only advisor turn on the Task 0
  commit hash (diff, proofs' outputs, both review verdicts) records ACCEPTED or REJECTED;
  REJECTED reverts Task 0 by a non-rewriting revert before any dispatch. Both review
  verdicts and this acceptance are recorded in the mission checkpoint.

**Alternative considered (named for the advisor's decision).** A worker-authored,
authoring-only Task 0: the worker writes the same files without executing anything, the
root's full gate for that one task is the core `scripts/verify.ps1` alone, and the
operator runs the four proofs and commits `offline_data/uv.lock` at the Task 0 to Task 1
boundary. It keeps the authoring inside the relay's journalled intent and outcome, its
bounded-path post-check and its token-shape scan, at the cost of a worker writing a
launcher it cannot run, a reviewed-policy change between Task 0 and Task 1, and an
operator commit of the lock in any case. The controller-session route above bypasses those
three relay checks and compensates with Steps 2, 5 and 7 and the controller's outgoing
token-shape scan before any publication. This revision recommends the controller-session
Task 0; the advisor's acceptance turn selects one of the two.

### Task 1 - The `ohlcv-csv/1` reader on the Task 0 scaffold

**Objective.** Deliver the strict reader with injected diagnostics, its fixtures and the
sub-project's boundary guards, on the committed Task 0 scaffold.

**Prerequisites.** Task 0 committed (the mission's base commit) and its proofs recorded;
`offline_data/.venv` synced by the operator. A missing environment is reported by the
worker, never provisioned by it.

**Files created.** `offline_data/src/crypto_lab_offline_data/candle_csv.py`,
`offline_data/src/crypto_lab_offline_data/diagnostics.py`,
`offline_data/src/crypto_lab_offline_data/providers.py`,
`offline_data/tests/unit/test_candle_csv.py`,
`offline_data/tests/unit/test_providers.py`,
`offline_data/tests/safety/test_boundaries.py`,
`offline_data/tests/fixtures/candles/btcusdt-1m-clean.valid.csv`,
`offline_data/tests/fixtures/candles/invalid/naive-timestamp.csv`,
`offline_data/tests/fixtures/candles/invalid/offset-timestamp.csv`,
`offline_data/tests/fixtures/candles/invalid/float-exponent.csv`,
`offline_data/tests/fixtures/candles/invalid/wrong-header.csv`,
`offline_data/tests/fixtures/candles/invalid/extra-column.csv`,
`offline_data/tests/fixtures/candles/invalid/empty.csv`,
`offline_data/tests/fixtures/candles/invalid/header-only.csv`.

**Files modified.** `offline_data/README.md` (the `ohlcv-csv/1` section),
`offline_data/tests/conftest.py` (shared fixtures).

**Interfaces consumed.** `CanonicalDecimal`, `format_decimal`, `require_utc`,
`Failure`, `Diagnostic`, `DiagnosticSeverity`, `DiagnosticCategory`,
`validate_prefixed_uuid4`.

**Interfaces produced.** `IdProvider`, `Clock` (section 5.4); `read_ohlcv_csv(path, *, ids, clock, max_rows, max_bytes) -> Success[tuple[CandleRow, ...]] | Failure`;
`CandleRow` (frozen dataclass: `open_time_utc: datetime`, `open/high/low/close/volume: Decimal`, `line: int`);
`refusal(code, *, line, value_length, ids, clock) -> Failure`;
`ProviderContractError` (diagnostics module, R7).

- [ ] **Step 0 Confirm the base (no execution).** The worktree is at the Task 0 commit;
  `offline_data/.venv` exists (synced by the operator's Task 0 proofs); the sub-project
  launcher spelling named in the task prompt is the committed one. Author the fixtures.
  The worker runs no environment profile; if the environment is missing it reports that
  and stops (P2-B2 handling is the operator's).
- [ ] **Step 1 Focused RED.**

| File | Test | Fails because |
|---|---|---|
| `tests/unit/test_candle_csv.py` | `test_clean_fixture_reads_sixty_rows_as_decimals_and_utc` | module absent |
| `tests/unit/test_candle_csv.py` | one test per invalid fixture asserting a `Failure` whose diagnostic carries the code, line and value length and never the value | module absent |
| `tests/unit/test_candle_csv.py` | `test_size_ceilings_refuse_without_truncation` | module absent |
| `tests/unit/test_providers.py` | injected ids and clock are used; production ids satisfy the core prefix grammar | module absent |
| `tests/safety/test_boundaries.py` | import purity of `crypto_lab_offline_data` (module census `candle_csv`, `diagnostics`, `providers` present and no forbidden imports) and the reader writes nothing (`tmp_path` and the working directory unchanged after reading a fixture) | module census absent; GREEN at Step 3 |
| `tests/safety/test_boundaries.py` | dependency pins, forbidden families, lock version equality, lock source record | guards GREEN by construction after Task 0; proven by a working-tree negative control (a temporarily altered pin or lock line, run RED, reverted, never committed) |

- [ ] **Step 2** Run the RED set through `invoke-offline-uv.ps1 pytest-focused tests/unit/test_candle_csv.py tests/unit/test_providers.py tests/safety/test_boundaries.py -q`; record the failures.
- [ ] **Step 3 Minimum GREEN.** Reader, diagnostics, providers.
- [ ] **Step 4 Focused GREEN.** `invoke-offline-uv.ps1 pytest-focused tests/unit/test_candle_csv.py tests/unit/test_providers.py tests/safety/test_boundaries.py -q` (the launcher's target grammar requires explicit `tests/...` paths, never a bare `tests`).
- [ ] **Step 5** `verify-offline.ps1` green; the core's `scripts/verify.ps1` green; independent review of R1, R2, R6 and the boundary tests (the launcher was reviewed in Task 0); commit
  `feat(offline-data): the ohlcv-csv/1 reader, its fixtures and the boundary guards`.

### Task 2 - Validation, normalization and checksums

**Objective.** The section 4 rule matrix and the section 5.2 container.

**Prerequisites.** Task 1 accepted.

**Files created.** `offline_data/src/crypto_lab_offline_data/validation.py`,
`offline_data/src/crypto_lab_offline_data/normalize.py`,
`offline_data/tests/unit/test_validation.py`, `offline_data/tests/unit/test_normalize.py`,
`offline_data/tests/fixtures/candles/btcusdt-1m-gaps-duplicates.valid.csv`,
`offline_data/tests/fixtures/candles/invalid/negative-price.csv`,
`offline_data/tests/fixtures/candles/invalid/high-below-low.csv`,
`offline_data/tests/fixtures/candles/invalid/unsorted.csv`,
`offline_data/tests/fixtures/candles/invalid/off-grid.csv`.

**Files modified.** `offline_data/src/crypto_lab_offline_data/__init__.py`,
`offline_data/README.md`.

**Interfaces produced.** `validate_series(rows, *, timeframe, ids, clock) -> Success[ValidatedSeries] | Failure`
(`ValidatedSeries`: rows, `missing_intervals: tuple[TimeInterval, ...]`,
`duplicate_intervals: tuple[DuplicateInterval, ...]`, `observations: tuple[str, ...]`,
`start_utc`, `end_utc`, `row_count`); `write_normalized_container(series, path) -> NormalizedContainer`
(`bytes_written`, `content_hash`, `normalized_checksum`, `row_count`).

- [ ] **Step 1 Focused RED.** One test per section 4 row for both valid fixtures and the
  four new invalid fixtures; container byte-exactness and checksum tests; `row_count`
  equals the container's line count; idempotency.
- [ ] **Step 2** Record the failures. - [ ] **Step 3 Minimum GREEN.** - [ ] **Step 4 Focused GREEN** (`pytest-focused tests/unit/test_validation.py tests/unit/test_normalize.py tests/unit/test_candle_csv.py -q`).
- [ ] **Step 5** `verify-offline.ps1` green; the core's `scripts/verify.ps1` green; review of R4, R5 and the no-fabrication rule; commit
  `feat(offline-data): validate and normalize ohlcv-csv/1 series with explicit gaps and duplicates`.

### Task 3 - Metadata emission, command entry and goldens

**Objective.** Emit `DatasetDescriptor` and `DatasetPartition` with the core's identity,
through a command, with goldens and the consumer check.

**Prerequisites.** Task 2 accepted.

**Files created.** `offline_data/src/crypto_lab_offline_data/metadata.py`,
`offline_data/src/crypto_lab_offline_data/__main__.py`,
`offline_data/src/crypto_lab_offline_data/cli.py`,
`offline_data/tests/unit/test_metadata.py`, `offline_data/tests/unit/test_cli.py`,
`offline_data/tests/integration/test_core_contract_roundtrip.py`,
`offline_data/tests/fixtures/candles/golden/btcusdt-1m-clean.descriptor.json`,
`offline_data/tests/fixtures/candles/golden/btcusdt-1m-clean.partitions.json`,
`offline_data/tests/fixtures/candles/golden/btcusdt-1m-clean.content_hash.txt`,
`offline_data/tests/fixtures/candles/golden/btcusdt-1m-gaps-duplicates.descriptor.json`,
`offline_data/tests/fixtures/candles/golden/btcusdt-1m-gaps-duplicates.partitions.json`,
`offline_data/tests/fixtures/candles/golden/btcusdt-1m-gaps-duplicates.content_hash.txt`.

**Files modified.** `offline_data/src/crypto_lab_offline_data/__init__.py`,
`offline_data/README.md`.

**Interfaces produced.** `build_dataset_metadata(series, container, *, instrument, timeframe, source, ids, clock) -> Success[DatasetBundle] | Failure`
(`DatasetBundle`: `descriptor`, `partitions`); `normalize_command(argv, *, ids, clock) -> int` writing
`descriptor.json`, `partitions.json`, `part-0000.ndjson` into `--output`; exit code 3 and no
output written on `ProviderContractError` (R7).

- [ ] **Step 1 Focused RED.** Descriptor and partition field mapping (section 5.1, every
  field), the section 5.4 content-hash construction, `validate_dataset_identity` passes,
  the clean fixture is `VALID` and the gaps-duplicates fixture `VALID_WITH_WARNINGS`
  (R4), the emitted JSON re-parses through the core models in strict JSON mode,
  `--output` handling of section 6, a refused input writes nothing, exit codes. The
  golden-equality tests are added after the first GREEN run captures the goldens.
- [ ] **Step 2** Record the failures. - [ ] **Step 3 Minimum GREEN.** - [ ] **Step 4 Focused GREEN** (`pytest-focused tests/unit/test_metadata.py tests/unit/test_cli.py tests/integration/test_core_contract_roundtrip.py -q`).
- [ ] **Step 5** `verify-offline.ps1` green; the core's `scripts/verify.ps1` green; review of R3 and the goldens; commit
  `feat(offline-data): emit dataset descriptor and partition metadata with the core identity hash`.

## 8. Verification and acceptance

- Task 0 (controller session): the four offline proofs of section 2.7, then
  `offline_data/scripts/verify-offline.ps1` green and the core `scripts/verify.ps1` green,
  run by the operator alone on the host and recorded in the mission checkpoint with the
  commit, the proofs' outputs, the two reviewer verdicts (Task 0 Steps 2 and 5) and the
  advisor's acceptance of the commit (Step 7); the per-task relay gate below applies from
  Task 1.
- Per worker task: `offline_data/scripts/verify-offline.ps1` (lock check, sync, format, lint,
  strict types, tests with branch coverage >= 98.61 percent, whitespace) green, then the
  core's `scripts/verify.ps1` green, each run alone on the host (the controller serializes
  heavy runs; the core verifier's format and lint stages traverse the sub-project and the
  repository's completion rule requires the full core verifier before completion is
  claimed).
- Per task: one independent review of the task diff; corrective rounds are incremental.
- Acceptance of the slice: Task 0 committed and reviewed, all three worker tasks accepted
  and published on
  `project-2-offline-data-implementation`; goldens committed; README documents the
  supported format, the limitations and the two reporting boundaries.

## 9. Early integration checks

1. After Task 3: the consumer round trip in `test_core_contract_roundtrip.py` (emitted
   JSON through the core models; hash recomputed by the core).
2. Slice 2 (Workstream A): the temporary-database contract test through
   `SqliteDatasetRepository` from the committed goldens; a mismatch is a shared-contract
   finding for Workstream A; nothing persistent is registered.
3. Slice 3 (Workstream A, after the Stage 9 merge): artifact finalization with the
   `DATASET` owner.

## 10. Rollback and completion

Every revision of this plan is re-hashed and independently re-reviewed before dispatch;
the mission gate pins the reviewed sha256 and commit. Each task is one commit on the
implementation branch; rollback is a non-rewriting revert.
The slice is complete when section 8 holds for Task 0 and all three worker tasks; the token recorded on
acceptance is `P2_SLICE1_PLAN_COMPLETE`.
