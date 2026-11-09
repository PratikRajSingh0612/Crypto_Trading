# Project 2 - Offline historical candle data: first bounded slice (implementation plan)

> **For agentic workers.** This plan is the authority for the tasks it names. The
> approved specification (`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md`)
> and the reviewed core source outrank any paraphrase here. Where this plan declares a
> reading of the specification, the reading is listed in section 1.6 and the independent
> reviewer confirms or refutes it before acceptance. Nothing in this plan authorizes
> network access, real downloads, exchange credentials, live trading, cloud deployment,
> GitNexus activation or a dependency acquisition.

**Status.** Draft for advisor acceptance and independent review (owner authorization
"TWO PARALLEL PRODUCT WORKSTREAMS", 2026-11-09, section 3). Not accepted.

**Planning base.** Repository `Crypto_Trading`, branch `project-2-offline-data-plan`
created from accepted `main` at commit `079395bec70f1deda406d0ca14b2d4bf79aaf063`.
The implementation worktree for this plan is created from the same commit as
`project-2-offline-data-implementation`.

**Prerequisites.** Project 1 Stages 1-8 accepted and merged (`main` 079395be). Stage 9
is in progress on `project-1-stage-9-implementation` and is NOT a prerequisite of this
slice; the dataset contracts this slice consumes are byte-identical on `main` and on the
Stage 9 branch (section 2.2 pins their blob identities). Slice 3 (core registration and
finalization through the artifact finalizer) waits for the Stage 9 milestone merge and
is a named forward obligation, not a task of this plan.

**Goal.** Read one local historical-candle fixture in one documented input format,
validate and normalize it under the core's dataset rules, and emit the dataset metadata
the core already defines (`DatasetDescriptor`, `DatasetPartition`) with a deterministic
content identity, deterministic tests, valid and invalid fixtures, and no change to the
core package, its lockfile or its guards.

**Architecture.** A self-contained sub-project `offline_data/` inside the repository with
its own `pyproject.toml`, `uv.lock`, managed-Python environment and launcher, consuming
the core package as a path dependency of its own environment. It never writes into the
core's environment. It is the "registered isolated runtime" pattern the specification
uses for components whose dependencies must not leak into the core (specification
section 6.2, 31.1; mission package `01_MISSION_AND_AUTHORITY.md:26`).

**Tech stack.** Managed CPython 3.12 selected by `uv` (the same interpreter family as
the core), standard library only for parsing and normalization (`csv`, `decimal`,
`datetime`, `hashlib`, `json`), the core package `crypto_lab` for the dataset models,
hashing profile, canonical JSON and UTC helpers. No pandas, pyarrow, polars or numpy.

**Spec.** Specification sections 6.2 (external components), 8.2 and 18.1-18.3 (datasets),
27.1 (`datasets` placement), 31.1 (isolated runtimes), 32 (Project 2 boundary); roadmap
`03_PRODUCT_ROADMAP.md:29-37` (P2 scope and acceptance).

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
- **Dependency acquisition.** None in this plan. The sub-project's own lockfile resolves
  from the local uv cache the core already populated (the four core runtime
  dependencies and their transitive closure). If the offline resolution of the
  sub-project lock fails, the exact missing distribution is reported once as acquisition
  boundary P2-B2 and the plan stops before Task 1 step 3; nothing is acquired.
- **Parquet boundary (P2-B1).** The specification makes dataset partitions Parquet files
  (specification lines 384, 1309). Parquet emission needs `pyarrow`, which is a prohibited
  family in the core and not approved for acquisition anywhere. This slice emits the
  validated normalized row stream, its checksums and the full metadata; the partition
  container is an explicitly labelled interim container (section 5.3). It is never
  presented as the production partition format and every descriptor it emits carries the
  limitation in `known_limitations` and a quality observation. Lifting P2-B1 is a
  separately authorized acquisition and a later task.
- **Raw data outside Git.** Fixtures are small deterministic non-secret inputs under
  `offline_data/tests/fixtures/` (specification line 1946 convention). Outputs land only
  in caller-chosen output directories or test temporary directories; nothing under the
  repository root is written at run time; the forbidden root directories
  (`tests/safety/test_forbidden_runtime_paths.py`) stay absent.
- **Determinism.** Identifiers (`ds_`, `part_`) and timestamps (`created_at_utc`,
  `imported_at_utc`) come from injected providers; tests inject fixed values. The content
  hash excludes them by the core's own hashing profile, so the golden hash of a fixture is
  stable across runs and machines.
- **Decimal and UTC.** Prices and volumes are `decimal.Decimal` from the exact source
  text; no float is ever constructed. Timestamps are timezone-aware UTC; naive values and
  non-UTC offsets are refused, never converted.
- **No silent fabrication.** Missing bars and duplicate bars are explicit records in the
  descriptor; rows are never interpolated, dropped silently or de-duplicated silently.
- **Test-first.** Every behaviour lands as a focused failing test, the minimum
  implementation, the focused passing test, then the sub-project's quality gates.

## 1. Goal, scope and exclusions

### 1.1 Goal

A deterministic offline pipeline `fixture -> validated rows -> normalized container +
checksums -> DatasetDescriptor + DatasetPartition metadata` for one input format and one
representative instrument, proven against the core's own models, hashing profile and
JSON schemas, inside an isolated sub-project environment.

### 1.2 In scope

| Area | Delivers | Owning task |
|---|---|---|
| Sub-project scaffold | `offline_data/` with pyproject, lock, launcher, verify script, README | Task 1 |
| Input contract `ohlcv-csv/1` | Strict reader: header, row grammar, Decimal and UTC parsing, bounded size | Task 1 |
| Validation | Ordering, duplicates, missing bars, invalid prices and volumes, timeframe grid, precision, timezone | Task 2 |
| Normalization | Canonical normalized rows, raw and normalized checksums, half-open interval | Task 2 |
| Metadata emission | `DatasetPartition`, `DatasetDescriptor`, `dataset_metadata_hash`, identity validation, canonical JSON files | Task 3 |
| Command entry | `python -m crypto_lab_offline_data normalize ...` writing to an output directory | Task 3 |
| Fixtures and goldens | One valid clean fixture, one valid-with-warnings fixture, nine invalid fixtures, golden descriptor and hash | Tasks 2-3 |

### 1.3 Out of scope

| Excluded | Reason | Owner |
|---|---|---|
| Real source verification (Binance archive layout, timestamp units, checksums, licensing) | Needs network; roadmap P2 first deliverable, separately authorized | later P2 task after authorization |
| Any download, acquisition or bounded smoke run | Not authorized | later P2 task after authorization |
| Parquet partition emission | P2-B1 (pyarrow prohibited, not acquired) | later P2 task after authorization |
| Registration into the core's SQLite dataset registry | Slice 2; consumer test owned by Workstream A | Workstream A forward obligation |
| Finalization through the artifact finalizer (`DATASET` owner) | Slice 3; needs the Stage 9 milestone merge | Workstream A forward obligation |
| Multiple input formats, multiple instruments, multi-partition datasets | Second slice | later P2 task |
| Changes to shared contracts (models, schemas, hashing profile) | Belong to Workstream A with consumer tests | Workstream A |
| Dashboard, engines, VectorBT research | Not this workstream | - |

### 1.4 Named forward obligations

1. **Slice 2 (Workstream A):** a core-side consumer test registering a descriptor and
   partitions emitted by this slice through `SqliteDatasetRepository.register` and
   reading them back by `content_hash` and `ordinal`. Input: the golden files this plan
   commits under `offline_data/tests/fixtures/candles/golden/`.
2. **Slice 3 (Workstream A, after the Stage 9 merge):** finalization of the normalized
   container as a `DATASET_INPUT`/`DATASET` artifact with the `DatasetArtifactOwner`.
3. **P2-B1 lift:** Parquet emission once `pyarrow` is an approved acquisition in the
   sub-project environment only; the interim container is then retired.
4. **Source verification:** the roadmap's first deliverable (official schema, timestamp
   units, archive checksums, licensing) and the real-format adapter it enables.

### 1.5 Carried notes

- The core's `Bar` evaluation model (`strategy/evaluation.py`) is not a dataset row
  contract and is not consumed; the normalized row schema of this slice is declared in
  section 5.2 and versioned by `column_schema_version`.
- The specification promises Parquet schema declarations under `schemas/artifacts`; none
  exist. This slice does not create them (shared-contract territory).

### 1.6 Escalations and declared readings the reviewer must confirm

- **R1 Placement.** A sub-project `offline_data/` inside the repository with its own
  environment is the correct reading of "outside the core's dependency/runtime boundary"
  (specification 6.2 and 31.1; roadmap: "Continue the existing Crypto_Trading repository";
  controller policy: no new publication remotes). Alternative refused: a separate
  repository (would need a new remote) or a package inside `src/crypto_lab` (would need
  prohibited families and guard edits).
- **R2 Input format.** A documented versioned CSV format `ohlcv-csv/1` (section 3) is the
  "one supported input format" for this slice. The Binance archive layout is NOT asserted
  from memory; its adapter follows the authorized source verification.
- **R3 Interim container.** Emitting a canonical NDJSON normalized container labelled
  `normalized-ndjson/0.1.0` with `known_limitations` and a quality observation naming
  P2-B1 does not "fake the required production output format" because it is never
  called a Parquet partition and the descriptor is `VALID_WITH_WARNINGS` at best.
- **R4 Validation status.** A fixture with no missing bars, no duplicates and no
  limitation other than the interim container is `VALID_WITH_WARNINGS` (the container
  observation is a quality fact); a fixture with gaps or duplicates is
  `VALID_WITH_WARNINGS` with interval records; any refused row makes the whole input
  `INVALID` with a diagnostic and no partition file.
- **R5 Half-open interval.** `start_utc` is the first bar's open time and `end_utc` is
  the last bar's open time plus one timeframe step; a gap is a `TimeInterval` from the
  first missing open time to the next present open time.
- **R6 Core consumption.** Consuming `crypto_lab` as a path dependency inside the
  sub-project's own environment keeps the core's lockfile and environment untouched and
  is the intended way to "use the existing contracts rather than inventing a parallel
  data model".

## 2. Authority, consumed interfaces, readings and reconciliation

### 2.1 Authority order

Specification; reviewed core source at the pinned blobs; this plan; the sub-project's
README. Advisor and reviewer output is advisory and cannot override the first three.

### 2.2 Consumed interfaces (pinned at `main` 079395be; identical on the Stage 9 branch)

<!-- consumed -->
| Symbol | Module (blob) | Contract |
|---|---|---|
| `DatasetDescriptor`, `DatasetPartition`, `TimeInterval`, `DuplicateInterval`, `RawSourceProvenance`, `DatasetDataType`, `DatasetValidationStatus` | `src/crypto_lab/datasets/models.py` (`9c5c5b99`) | Strict frozen canonical models; `extra=forbid`; unique sorted intervals; `VALID` cannot carry warning facts; zero-row partition needs an observation; OHLCV requires `timeframe`; venue equals instrument venue |
| `dataset_metadata_hash`, `validate_dataset_identity`, `DATASET_METADATA_V1` | `src/crypto_lab/datasets/hashing.py` (`bb5f05f7`) | SHA-256 over canonical JSON of `{schema_version, hashing_profile, payload}` excluding ids, timestamps of creation/import and partition paths; partitions ordered by `partition_ids` with `ordinal == index` |
| `DatasetRepository` | `src/crypto_lab/datasets/ports.py` (`f4d2f5a3`) | Read only here: documents the registration contract slice 2 will satisfy |
| `dataset-descriptor-v1`, `dataset-partition-v1` JSON schemas | `schemas/datasets/*.schema.json` (`d997ed79`, `7ea31efe`) | Emitted JSON must re-validate through the core models in strict JSON mode |
| `InstrumentRef`, `AssetCode`, `MarketType` | `src/crypto_lab/domain/records.py` | `canonical_id == VENUE:BASE/QUOTE:MARKET` |
| `UtcDateTime`, `require_utc`, `format_utc` | `src/crypto_lab/domain/time.py` | Timezone-aware UTC only; JSON form `YYYY-MM-DDTHH:MM:SS(.ffffff)?Z` |
| `CanonicalDecimal`, `PositiveDecimal`, `NonNegativeDecimal` | `src/crypto_lab/domain/financial.py` | Python `Decimal` input; canonical finite string in JSON; no float |
| `canonical_json_bytes` | `src/crypto_lab/domain/canonical_json.py` | Sorted keys, compact separators, UTF-8, float forbidden |
| `Success`, `Failure`, `Diagnostic` | `src/crypto_lab/domain/results.py`, `domain/diagnostics.py` | Refusals are `Failure` values carrying a `Diagnostic`; no exceptions cross the sub-project boundary |

The implementer re-reads each consumed module before use and refuses to proceed if a
blob differs from the pinned identity (report the drift; do not adapt silently).

### 2.3 Placement decisions

- Package name `crypto_lab_offline_data`, distribution name `crypto-lab-offline-data`,
  version `0.1.0`, under `offline_data/src/`.
- The sub-project's own `scripts/invoke-offline-uv.ps1` mirrors the core launcher's
  closed profile set (`lock-check`, `lock-resolve-offline`, `sync`, `pytest-focused`,
  `ruff-format-all`, `ruff-check-all`, `mypy-all`) with the same `--offline`,
  `--managed-python`, `--no-python-downloads`, `--no-config` controls, pinned to
  `offline_data/.venv`. Its distinct file name keeps the core's host-wide competition
  rule (`invoke-uv.ps1`, `verify.ps1`) from treating sub-project runs as core runs.
- `offline_data/scripts/verify-offline.ps1` runs: lock check, sync, format check, lint,
  strict types, test suite with branch coverage, Git whitespace check. The coverage
  floor is 98.61 percent branch coverage, the same figure the current core stage holds,
  so no different testing policy is adopted.
- `offline_data/.venv` is ignored by the root `.gitignore` pattern `.venv/` without
  editing that protected file. `offline_data/uv.lock` is committed.

### 2.4 Frozen-byte and contract constraints

The core package is consumed exactly as built from the repository root
(`[tool.uv.sources] crypto_lab = { path = "../" }`, non-editable). No core module is
monkeypatched, subclassed with overridden validators, or re-implemented.

### 2.5 Declared readings of the specification

R1-R6 in section 1.6. The reviewer confirms each against the quoted specification lines
before acceptance; a refuted reading stops the task that depends on it.

### 2.6 Closed-world guard reconciliation

**Core guards: no transition.** No path under `src/crypto_lab` or `tests` changes, so
the Stage 3-9 censuses (source files, import roots, deferred names) are untouched and
need no reconciliation table. The core's `ruff-check-all` lints every Python file under
the repository, so sub-project code must pass the core's ruff configuration unchanged;
the core's `mypy-all` (`files = src, tests, scripts`), `pytest` (`testpaths = tests`) and
coverage (`source = crypto_lab`) do not include the sub-project.

**Sub-project guards (created by Task 1):** `offline_data/tests/safety/test_boundaries.py`
pins the sub-project's runtime dependency list to exactly `crypto-lab` (path) and nothing
else, forbids `pandas`, `pyarrow`, `polars`, `numpy`, `requests`, `httpx` and the other
prohibited families by name in the sub-project lock, forbids any `socket`, `urllib`,
`http`, `subprocess` or `os.environ` import in `crypto_lab_offline_data`, and asserts no
file is written outside the caller's output directory.

### 2.7 Toolchain gates

Managed CPython 3.12 via `uv python find --managed-python --system --no-python-downloads 3.12`
(same prerequisite as the core); ruff and mypy pinned to the versions the core lock
already carries (so the local cache resolves them offline); pytest and pytest-cov
likewise.

### 2.8 Dependency acquisition gates

None. P2-B1 (pyarrow) and P2-B2 (any distribution the offline lock cannot resolve) are
reporting boundaries, not acquisitions.

## 3. Input contract `ohlcv-csv/1`

- UTF-8 text, LF or CRLF line endings, first line exactly
  `open_time_utc,open,high,low,close,volume`.
- Each data row has exactly six fields. `open_time_utc` is `YYYY-MM-DDTHH:MM:SSZ`
  (seconds precision, literal `Z`); any other form, including naive values and numeric
  offsets, is refused. `open`, `high`, `low`, `close` are positive finite decimal strings
  (digits with an optional single `.`; no exponent, no sign, no leading `+`); `volume` is
  a non-negative decimal string of the same grammar.
- Size ceilings: at most 1,048,576 rows and 64 MiB per input; exceeding either is a
  refusal, never a truncation.
- Empty file, header-only file, wrong header, wrong field count, blank line inside the
  body, non-UTF-8 bytes: refused with a diagnostic naming the one-based line number and
  the rule, never the offending value (the value may be sensitive material by policy;
  only its length and position are recorded).
- Identity of the raw input: `raw_checksum` is SHA-256 of the exact input bytes.

## 4. Validation and normalization rules

| Rule | Behaviour | Descriptor effect |
|---|---|---|
| Ordering | Rows must be non-decreasing in `open_time_utc`; a decrease is a refusal (`INVALID`) | diagnostic |
| Duplicates | Equal `open_time_utc` on consecutive rows: all rows kept in the normalized container; a `DuplicateInterval(start=open_time, end=open_time + step, duplicate_count=n)` recorded; rows with equal time but different values additionally raise a quality observation | `duplicate_intervals`, `VALID_WITH_WARNINGS` |
| Timeframe grid | Every `open_time_utc` must sit on the timeframe grid (`open_time % step == 0` from the Unix epoch); off-grid is a refusal | diagnostic |
| Missing bars | A gap of `k >= 1` steps between consecutive distinct open times records `TimeInterval(start=first missing open, end=next present open)`; never filled | `missing_intervals`, `VALID_WITH_WARNINGS` |
| Price sanity | `low <= open, close <= high`, all prices positive; violation is a refusal | diagnostic |
| Volume | non-negative; violation is a refusal | diagnostic |
| Precision | Decimal values are carried exactly; the normalized form is the canonical decimal string the core's `CanonicalDecimal` accepts | `normalized_checksum` |
| Timezone | Only `Z`; naive or offset values are refusals | diagnostic |
| Interval | `start_utc = first open`, `end_utc = last open + step` (half-open) | `start_utc`, `end_utc` |
| Row count | distinct-open-time count is `row_count`; zero rows is a refusal for this slice (an empty dataset is not a representative dataset) | `row_count` |

Timeframe grammar is the core's `Timeframe` pattern; this slice supports `1m`, `5m`,
`15m`, `1h`, `4h`, `1d` and refuses other values with a diagnostic (month and week
steps are not on a fixed-second grid and are out of scope).

## 5. Metadata emission

### 5.1 Descriptor and partition mapping

| Field | Source |
|---|---|
| `schema_version` | `"1.0.0"` |
| `dataset_id`, `partition_id` | injected id provider (`ds_<uuid4>`, `part_<uuid4>`); tests inject fixed ids |
| `source` | command argument `--source` (bounded text), default `local-fixture` |
| `venue`, `instrument` | parsed from `--instrument VENUE:BASE/QUOTE:MARKET` into `InstrumentRef` |
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
| `partition_ids` | the one partition |
| `missing_intervals`, `duplicate_intervals` | section 4 |
| `diagnostic_ids` | empty on success (an `INVALID` input emits no descriptor file; the failure is returned as the command result) |
| `raw_checksums`, `normalized_checksums` | one entry each, partition order |
| `column_schema_version` | `"0.1.0"` (section 5.2) |
| `known_limitations` | at least the P2-B1 text: `"interim container normalized-ndjson/0.1.0; Parquet partition emission requires the pyarrow acquisition (P2-B1)"` |
| `content_hash` | `dataset_metadata_hash(descriptor_without_hash, partitions)` then `validate_dataset_identity` |
| partition `relative_path` | `datasets/<dataset_id>/part-0000.ndjson` (registry-relative POSIX) |
| partition `content_hash` | SHA-256 of the container bytes |
| partition `quality_observations` | the P2-B1 observation plus the duplicate-value observation when raised |

### 5.2 Normalized row schema `0.1.0`

One JSON object per line, keys in this order after canonicalization:
`close`, `high`, `low`, `open`, `open_time_utc`, `volume`; numeric fields are canonical
decimal strings; `open_time_utc` is the core UTC string form. Lines end with `\n`; the
file ends with a final newline; `normalized_checksum` is SHA-256 of the whole container.

### 5.3 Interim container

The container is written as `part-0000.ndjson` under the caller's output directory next
to `descriptor.json` and `partitions.json` (canonical JSON of the models). The README and
every descriptor name it as interim (P2-B1). No code path, file name or documentation
calls it a Parquet partition.

## 6. Test strategy, fixtures and goldens

Fixtures under `offline_data/tests/fixtures/candles/`:

- `btcusdt-1m-clean.valid.csv`: 60 consecutive 1m bars, `BINANCE:BTC/USDT:SPOT`
  (synthetic values; the instrument string exercises the canonical id grammar, not a
  claim about real market data).
- `btcusdt-1m-gaps-duplicates.valid.csv`: 60 bars with one 3-bar gap and one duplicated
  open time (identical values) and one duplicated open time (differing values).
- `invalid/`: `naive-timestamp.csv`, `offset-timestamp.csv`, `float-exponent.csv`,
  `negative-price.csv`, `high-below-low.csv`, `unsorted.csv`, `off-grid.csv`,
  `wrong-header.csv`, `extra-column.csv`, `empty.csv`, `header-only.csv`.
- `golden/`: `btcusdt-1m-clean.descriptor.json`, `btcusdt-1m-clean.partitions.json`,
  `btcusdt-1m-clean.content_hash.txt`, and the same three for the gaps-duplicates fixture,
  produced with the fixed test ids and clock. Goldens are review oracles: no regeneration
  command.

Deterministic tests (`offline_data/tests/unit/`): reader grammar (one test per refusal),
rule matrix of section 4 (one test per row, both fixtures), normalization bytes and
checksums, descriptor and partition construction, golden equality, identity validation,
re-run idempotency (same bytes, same hash), output-directory confinement (nothing
written outside; `..` and absolute paths in `--output` refused), size ceilings, the
boundary tests of section 2.6. A consumer check re-parses the emitted JSON through the
core models in strict JSON mode and recomputes the hash with the core's function.

## 7. Task decomposition

Each task: test-first, one commit, clean worktree, `offline_data/scripts/verify-offline.ps1`
green before the commit. The sub-project never touches the core's paths.

### Task 1 - Sub-project scaffold, launcher, verify script and the `ohlcv-csv/1` reader

**Objective.** Create the isolated sub-project and the strict reader.

**Prerequisites.** Managed CPython 3.12 present; the local uv cache resolves the core's
runtime closure offline (otherwise boundary P2-B2 is reported and the plan stops).

**Files created.** `offline_data/pyproject.toml`, `offline_data/uv.lock`,
`offline_data/README.md`, `offline_data/scripts/invoke-offline-uv.ps1`,
`offline_data/scripts/verify-offline.ps1`, `offline_data/src/crypto_lab_offline_data/__init__.py`,
`offline_data/src/crypto_lab_offline_data/candle_csv.py`,
`offline_data/src/crypto_lab_offline_data/diagnostics.py`,
`offline_data/tests/conftest.py`, `offline_data/tests/unit/test_candle_csv.py`,
`offline_data/tests/safety/test_boundaries.py`,
`offline_data/tests/fixtures/candles/btcusdt-1m-clean.valid.csv`,
`offline_data/tests/fixtures/candles/invalid/naive-timestamp.csv`,
`offline_data/tests/fixtures/candles/invalid/offset-timestamp.csv`,
`offline_data/tests/fixtures/candles/invalid/float-exponent.csv`,
`offline_data/tests/fixtures/candles/invalid/wrong-header.csv`,
`offline_data/tests/fixtures/candles/invalid/extra-column.csv`,
`offline_data/tests/fixtures/candles/invalid/empty.csv`,
`offline_data/tests/fixtures/candles/invalid/header-only.csv`.

**Files modified.** None.

**Interfaces consumed.** `CanonicalDecimal`, `require_utc`, `Failure`, `Diagnostic`.

**Interfaces produced.** `read_ohlcv_csv(path, *, max_rows, max_bytes) -> Success[tuple[CandleRow, ...]] | Failure`;
`CandleRow` (frozen dataclass: `open_time_utc: datetime`, `open/high/low/close/volume: Decimal`, `line: int`).

- [ ] **Step 1 Focused RED.**

| File | Test | Fails because |
|---|---|---|
| `tests/unit/test_candle_csv.py` | `test_clean_fixture_reads_sixty_rows_as_decimals_and_utc` | module absent |
| `tests/unit/test_candle_csv.py` | one test per invalid fixture asserting a `Failure` whose diagnostic names the line and rule and never the value | module absent |
| `tests/unit/test_candle_csv.py` | `test_size_ceilings_refuse_without_truncation` | module absent |
| `tests/safety/test_boundaries.py` | dependency list, forbidden families, forbidden imports, no root writes | sub-project absent |

- [ ] **Step 2** Run the RED set through `invoke-offline-uv.ps1 pytest-focused`; record the failures.
- [ ] **Step 3 Minimum GREEN.** Scaffold, lock offline, reader, diagnostics.
- [ ] **Step 4 Focused GREEN.** `pytest-focused offline_data/tests -q`.
- [ ] **Step 5** `verify-offline.ps1` green; independent review of R1, R2, the launcher and the boundary tests; commit
  `feat(offline-data): scaffold the isolated sub-project and the ohlcv-csv/1 reader`.

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

**Interfaces produced.** `validate_series(rows, *, timeframe) -> Success[ValidatedSeries] | Failure`
(`ValidatedSeries`: rows, `missing_intervals: tuple[TimeInterval, ...]`,
`duplicate_intervals: tuple[DuplicateInterval, ...]`, `observations: tuple[str, ...]`,
`start_utc`, `end_utc`, `row_count`); `write_normalized_container(series, path) -> NormalizedContainer`
(`bytes_written`, `content_hash`, `normalized_checksum`, `row_count`).

- [ ] **Step 1 Focused RED.** One test per section 4 row for both valid fixtures and the
  four new invalid fixtures; container byte-exactness and checksum tests; idempotency.
- [ ] **Step 2** Record the failures. - [ ] **Step 3 Minimum GREEN.** - [ ] **Step 4 Focused GREEN.**
- [ ] **Step 5** `verify-offline.ps1` green; review of R4, R5 and the no-fabrication rule; commit
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
(`DatasetBundle`: `descriptor`, `partitions`); `normalize_command(argv) -> int` writing
`descriptor.json`, `partitions.json`, `part-0000.ndjson` into `--output`.

- [ ] **Step 1 Focused RED.** Descriptor and partition field mapping (section 5.1), content
  hash equals the golden, `validate_dataset_identity` passes, the emitted JSON re-parses
  through the core models in strict JSON mode, `--output` confinement, `INVALID` input
  writes nothing, exit codes.
- [ ] **Step 2** Record the failures. - [ ] **Step 3 Minimum GREEN.** - [ ] **Step 4 Focused GREEN.**
- [ ] **Step 5** `verify-offline.ps1` green; review of R3, R6 and the goldens; commit
  `feat(offline-data): emit dataset descriptor and partition metadata with the core identity hash`.

## 8. Verification and acceptance

- Per task: `offline_data/scripts/verify-offline.ps1` (lock check, sync, format, lint,
  strict types, tests with branch coverage >= 98.61 percent, whitespace) green, run alone
  on the host (never concurrently with the core's `verify.ps1`; the controller serializes
  heavy runs).
- Per task: one independent review of the task diff; corrective rounds are incremental.
- The core's own `scripts/verify.ps1` is NOT part of this plan's gate because no core
  path changes; the core's `ruff-check-all` still covers the new Python files, so the
  implementer runs it once per task to prove the sub-project code is clean under the
  core configuration (read-only use of the core launcher; no core file changes).
- Acceptance of the slice: all three tasks accepted and published on
  `project-2-offline-data-implementation`; goldens committed; README documents the
  supported format, the limitations and the two reporting boundaries.

## 9. Early integration checks

1. After Task 3: the consumer round trip in `test_core_contract_roundtrip.py` (emitted
   JSON through the core models; hash recomputed by the core).
2. Slice 2 (Workstream A): registration through `SqliteDatasetRepository` from the
   committed goldens; a mismatch is a shared-contract finding for Workstream A.
3. Slice 3 (Workstream A, after the Stage 9 merge): artifact finalization with the
   `DATASET` owner.

## 10. Rollback and completion

Each task is one commit on the implementation branch; rollback is a non-rewriting revert.
The slice is complete when section 8 holds for all three tasks; the token recorded on
acceptance is `P2_SLICE1_PLAN_COMPLETE`.
