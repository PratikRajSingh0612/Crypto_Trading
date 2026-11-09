# Project 2 - Offline historical candle data: first bounded slice (implementation plan)

> **For agentic workers.** This plan is the authority for the tasks it names. The
> approved specification (`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md`)
> and the reviewed core source outrank any paraphrase here. Where this plan declares a
> reading of the specification, the reading is listed in section 1.6 and the independent
> reviewer confirms or refutes it before acceptance. Nothing in this plan authorizes
> network access, real downloads, exchange credentials, live trading, cloud deployment,
> GitNexus activation or a dependency acquisition.

**Status.** Revision 2 (after independent review round 1, verdict REQUEST_CHANGES on
sha256 `44174509...`): for advisor acceptance and independent review (owner authorization
"TWO PARALLEL PRODUCT WORKSTREAMS", 2026-11-09, section 3). Not accepted.

**Planning base.** Repository `Crypto_Trading`, branch `project-2-offline-data-plan`
created from accepted `main` at commit `079395bec70f1deda406d0ca14b2d4bf79aaf063`.
The implementation worktree for this plan is created from the same commit as
`project-2-offline-data-implementation`.

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
  acquisition boundary P2-B2 and the plan stops before Task 1 step 3; nothing is acquired.
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

## 1. Goal, scope and exclusions

### 1.1 Goal

A deterministic offline pipeline `fixture -> validated rows -> normalized container +
checksums -> DatasetDescriptor + DatasetPartition metadata` for one input format and one
representative instrument, proven against the core's own models, hashing profile and
JSON schemas, inside an isolated sub-project environment.

### 1.2 In scope

| Area | Delivers | Owning task |
|---|---|---|
| Sub-project scaffold | `offline_data/` with pyproject, pinned lock, launcher, verify script, README | Task 1 |
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
  data model". Task 1 proves that the `[tool.uv.sources]` path source is honoured under
  the launcher's `--no-config` controls (section 2.7); if it is not, the plan stops as
  P2-B2 with the exact uv message.

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
`ValueError` and Pydantic `ValidationError` are caught at the sub-project boundary and
converted to `Failure`; no exception crosses the sub-project's public functions.

### 2.3 Placement decisions

- Package name `crypto_lab_offline_data`, distribution name `crypto-lab-offline-data`,
  version `0.1.0`, under `offline_data/src/`, `requires-python = ">=3.12,<3.13"`.
- `offline_data/pyproject.toml` carries its own `[tool.ruff]` (`src = ["src", "tests"]`,
  the core's select set, `line-ending = "lf"`, per-file `S101` for `tests/**/*.py`),
  `[tool.mypy]` (strict, `files = ["src", "tests"]`), `[tool.pytest.ini_options]`
  (`testpaths = ["tests"]`, branch coverage on `crypto_lab_offline_data`,
  `--cov-fail-under=90` mirroring the core's configured floor) and `[tool.coverage]`.
  The core's `ruff-check-all` (`ruff check .` from the repository root) traverses
  `offline_data/` and applies this nested configuration by hierarchical discovery; that
  stage of the core's `verify.ps1` must stay green over the sub-project.
- The sub-project's own `scripts/invoke-offline-uv.ps1` mirrors the core launcher's
  closed profile set (`lock-check`, `lock-resolve-offline`, `sync`, `pytest-focused`,
  `ruff-format-all`, `ruff-check-all`, `mypy-all`) with the same `--offline`,
  `--managed-python`, `--no-python-downloads`, `--no-config` controls, rooted at
  `offline_data/` (its `pytest-focused` takes targets under `offline_data/tests/`,
  spelled `tests/...` relative to that root) and pinned to `offline_data/.venv`. Its
  distinct file name matters for the controller's competition rule only across
  worktrees; inside one worktree every launcher run is competition, which is why section
  8 runs verification alone.
- `offline_data/scripts/verify-offline.ps1` runs: lock check, sync, format check, lint,
  strict types, test suite with branch coverage, Git whitespace check. The branch
  coverage floor is 98.61 percent, the figure the current core stage plan holds as its
  acceptance requirement (the core's configured pytest floor is 90 percent); the
  sub-project adopts both so no different testing policy is introduced.
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

R1-R6 in section 1.6. The reviewer confirms each against the quoted lines before
acceptance; a refuted reading stops the task that depends on it.

### 2.6 Closed-world guard reconciliation

**Core guards: no transition.** No path under `src/crypto_lab`, `tests`, `schemas` or
`scripts` changes, so the Stage 3-9 censuses (source files, import roots, deferred
names) are untouched and need no reconciliation table. Core stages that reach the
sub-project: only `ruff-check-all` (section 2.3). Core stages that do not: `mypy-all`
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
records `crypto-trading-lab` with a `directory = "../"` source; and asserts no file is
written outside the caller's output directory.

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
  `librt==0.15.0`, `hatchling==1.31.0`, `trove-classifiers==2026.6.1.19`,
  `types-pyyaml==6.0.12.20260815`.

Task 1 step 3 proves, in this order and offline: `lock-resolve-offline` succeeds;
`lock-check` passes; `offline_data/uv.lock` records `crypto-trading-lab` with a
`directory = "../"` source; `sync` builds the core wheel without isolation. Any failure is
reported once with the exact uv message as P2-B2 and the plan stops there.

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
  the rule, never the offending value (only its length and position are recorded).
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
  against its prefix; the production provider mints UUID4; tests inject fixed values.
- `Clock` protocol (sub-project): `now_utc() -> datetime` (timezone-aware UTC); tests
  inject a fixed instant.
- Diagnostics: `error_code` from the closed set `OFFLINE_DATA.CSV_ENCODING`,
  `OFFLINE_DATA.CSV_HEADER`, `OFFLINE_DATA.CSV_ROW_SHAPE`, `OFFLINE_DATA.CSV_TIMESTAMP`,
  `OFFLINE_DATA.CSV_NUMBER`, `OFFLINE_DATA.SIZE_CEILING`, `OFFLINE_DATA.ORDERING`,
  `OFFLINE_DATA.TIMEFRAME_GRID`, `OFFLINE_DATA.PRICE_SANITY`, `OFFLINE_DATA.VOLUME`,
  `OFFLINE_DATA.EMPTY_SERIES`, `OFFLINE_DATA.OUTPUT_DIRECTORY`; `category`
  `SCHEMA_VALIDATION`; `source_component = "crypto-lab-offline-data"`;
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

Each task: test-first, one commit, clean worktree, `offline_data/scripts/verify-offline.ps1`
green before the commit, plus one run of the core's `ruff-check-all` to prove the
sub-project is clean under the core's lint stage. The sub-project never touches the
core's paths.

### Task 1 - Sub-project scaffold, pinned environment, launcher, verify script and the `ohlcv-csv/1` reader

**Objective.** Create the isolated sub-project, prove the offline environment, and
deliver the strict reader with injected diagnostics.

**Prerequisites.** Managed CPython 3.12 present; the local uv cache resolves the pinned
closure of section 2.7 offline (otherwise boundary P2-B2 is reported and the plan stops).

**Files created.** `offline_data/pyproject.toml`, `offline_data/uv.lock`,
`offline_data/README.md`, `offline_data/scripts/invoke-offline-uv.ps1`,
`offline_data/scripts/verify-offline.ps1`, `offline_data/src/crypto_lab_offline_data/__init__.py`,
`offline_data/src/crypto_lab_offline_data/candle_csv.py`,
`offline_data/src/crypto_lab_offline_data/diagnostics.py`,
`offline_data/src/crypto_lab_offline_data/providers.py`,
`offline_data/tests/conftest.py`, `offline_data/tests/unit/test_candle_csv.py`,
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

**Files modified.** None.

**Interfaces consumed.** `CanonicalDecimal`, `format_decimal`, `require_utc`,
`Failure`, `Diagnostic`, `DiagnosticSeverity`, `DiagnosticCategory`,
`validate_prefixed_uuid4`.

**Interfaces produced.** `IdProvider`, `Clock` (section 5.4); `read_ohlcv_csv(path, *, ids, clock, max_rows, max_bytes) -> Success[tuple[CandleRow, ...]] | Failure`;
`CandleRow` (frozen dataclass: `open_time_utc: datetime`, `open/high/low/close/volume: Decimal`, `line: int`);
`refusal(code, *, line, value_length, ids, clock) -> Failure`.

- [ ] **Step 1 Focused RED.**

| File | Test | Fails because |
|---|---|---|
| `tests/unit/test_candle_csv.py` | `test_clean_fixture_reads_sixty_rows_as_decimals_and_utc` | module absent |
| `tests/unit/test_candle_csv.py` | one test per invalid fixture asserting a `Failure` whose diagnostic carries the code, line and value length and never the value | module absent |
| `tests/unit/test_candle_csv.py` | `test_size_ceilings_refuse_without_truncation` | module absent |
| `tests/unit/test_providers.py` | injected ids and clock are used; production ids satisfy the core prefix grammar | module absent |
| `tests/safety/test_boundaries.py` | dependency pins, forbidden families, forbidden imports, lock source record, no root writes | sub-project absent |

- [ ] **Step 2** Run the RED set through `invoke-offline-uv.ps1 pytest-focused`; record the failures.
- [ ] **Step 3 Minimum GREEN.** Scaffold; the four offline proofs of section 2.7 in order; reader, diagnostics, providers.
- [ ] **Step 4 Focused GREEN.** `invoke-offline-uv.ps1 pytest-focused tests -q`.
- [ ] **Step 5** `verify-offline.ps1` green; the core's `ruff-check-all` green; independent review of R1, R2, R6, the launcher and the boundary tests; commit
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

**Interfaces produced.** `validate_series(rows, *, timeframe, ids, clock) -> Success[ValidatedSeries] | Failure`
(`ValidatedSeries`: rows, `missing_intervals: tuple[TimeInterval, ...]`,
`duplicate_intervals: tuple[DuplicateInterval, ...]`, `observations: tuple[str, ...]`,
`start_utc`, `end_utc`, `row_count`); `write_normalized_container(series, path) -> NormalizedContainer`
(`bytes_written`, `content_hash`, `normalized_checksum`, `row_count`).

- [ ] **Step 1 Focused RED.** One test per section 4 row for both valid fixtures and the
  four new invalid fixtures; container byte-exactness and checksum tests; `row_count`
  equals the container's line count; idempotency.
- [ ] **Step 2** Record the failures. - [ ] **Step 3 Minimum GREEN.** - [ ] **Step 4 Focused GREEN.**
- [ ] **Step 5** `verify-offline.ps1` green; the core's `ruff-check-all` green; review of R4, R5 and the no-fabrication rule; commit
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
`descriptor.json`, `partitions.json`, `part-0000.ndjson` into `--output`.

- [ ] **Step 1 Focused RED.** Descriptor and partition field mapping (section 5.1, every
  field), the section 5.4 content-hash construction, `validate_dataset_identity` passes,
  the clean fixture is `VALID` and the gaps-duplicates fixture `VALID_WITH_WARNINGS`
  (R4), the emitted JSON re-parses through the core models in strict JSON mode,
  `--output` handling of section 6, a refused input writes nothing, exit codes. The
  golden-equality tests are added after the first GREEN run captures the goldens.
- [ ] **Step 2** Record the failures. - [ ] **Step 3 Minimum GREEN.** - [ ] **Step 4 Focused GREEN.**
- [ ] **Step 5** `verify-offline.ps1` green; the core's `ruff-check-all` green; review of R3 and the goldens; commit
  `feat(offline-data): emit dataset descriptor and partition metadata with the core identity hash`.

## 8. Verification and acceptance

- Per task: `offline_data/scripts/verify-offline.ps1` (lock check, sync, format, lint,
  strict types, tests with branch coverage >= 98.61 percent, whitespace) green, run alone
  on the host (never concurrently with the core's `verify.ps1`; the controller serializes
  heavy runs), plus the core's `ruff-check-all` green.
- Per task: one independent review of the task diff; corrective rounds are incremental.
- The core's own `scripts/verify.ps1` is NOT part of this plan's gate because no core
  path changes; its lint stage is the one stage that traverses the sub-project and is
  proven per task as above.
- Acceptance of the slice: all three tasks accepted and published on
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

Each task is one commit on the implementation branch; rollback is a non-rewriting revert.
The slice is complete when section 8 holds for all three tasks; the token recorded on
acceptance is `P2_SLICE1_PLAN_COMPLETE`.
