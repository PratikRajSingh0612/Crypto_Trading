# Crypto Trading Lab - offline historical candle data (`offline_data`)

**Status:** Project 2, first bounded slice committed (Tasks 0 to 3 of
`docs/superpowers/plans/2026-11-09-project-2-offline-data-first-slice-implementation-plan.md`,
revision 22); second slice, the `binance-spot-kline-csv/1` reader of
`docs/superpowers/plans/2026-11-10-project-2-binance-kline-reader-plan.md` (revision 3),
authored and awaiting the controller's verification, independent review and acceptance.

| Task | Delivers | Status |
|---|---|---|
| 0 | scaffold, launcher, verify script, pinned lock | committed |
| 1 | the `ohlcv-csv/1` reader (`candle_csv`), refusal diagnostics and the provider contract exception (`diagnostics`), injected identity and clock providers (`providers`), fixtures, boundary guards | committed |
| 2 | section 4 validation with explicit missing and duplicate intervals (`validation`), the interim normalized container, its checksums and the raw input checksum (`normalize`), five fixtures, the writer's exclusive-create and partial-file-removal pins in the boundary guards | committed |
| 3 | `DatasetDescriptor` and `DatasetPartition` emission with the core content hash (`metadata`), the `normalize` command and its module entry point (`cli`, `__main__`), six golden files, the consumer round trip, the one new refusal code `OFFLINE_DATA.METADATA_FIELD` with its closed-set pin, the command's directory-creation, JSON-write and reverse-order-removal pins in the boundary guards | committed |
| second slice, Task 1 | the `binance-spot-kline-csv/1` reader with explicit timestamp units (`binance_kline_csv`), the `--input-format` and `--timestamp-unit` arguments, the `InputFormat` source-identity table and the P2-B3 limitation (`metadata`), the one new refusal code `OFFLINE_DATA.TIMESTAMP_UNIT`, twenty-one SYNTHETIC fixtures and nine goldens | authored; awaits the controller's verification, independent review and acceptance |

Pending after the second slice and outside it: registration of the emitted metadata into a
core dataset registry (a temporary-database contract test, placed at
`offline_data/tests/integration/test_sqlite_dataset_registration.py` under the delegated
decision in section 1 of
`docs/superpowers/plans/2026-11-11-project-2-sqlite-dataset-registration-contract-plan.md`
and fed by the committed goldens; its verification, review and acceptance are recorded in
controller evidence), finalization through the artifact finalizer (after the Stage 9 merge),
Parquet emission (the P2-B1 lift) and the real-source verification. No interim container
enters a persistent registry, and no real Binance archive has been ingested.

## Scope

This sub-project is Project 2 in bounded slices: read one local historical-candle file in
one of two documented input formats (`ohlcv-csv/1`; `binance-spot-kline-csv/1`, an
already extracted Binance Spot kline CSV with a declared timestamp unit), validate and
normalize it under the core's dataset rules, and emit the dataset metadata the core
already defines (`DatasetDescriptor`, `DatasetPartition`) with a deterministic content
identity. Everything is offline: no download, no exchange or broker integration, no
credentials, no live trading, no cloud or server deployment.

## Placement: outside the core's dependency and runtime boundary

`offline_data/` is a self-contained Python sub-project inside the repository. It has
its own `pyproject.toml`, its own `uv.lock`, its own managed-Python environment
(`offline_data/.venv`, ignored by the root `.gitignore` pattern `.venv/`) and its own
launcher. It consumes the core distribution `crypto-trading-lab` as a non-editable path
dependency (`[tool.uv.sources] crypto-trading-lab = { path = "../" }`) built from the
repository root into the sub-project environment. It never writes into the core's
environment, lockfile, source tree or guards.

The complete closure is pinned with `==` to the versions the root `uv.lock` already
resolved: the runtime closure as uv `constraint-dependencies` and the development tools
in the `dev` dependency group, so the offline lock resolves from the local uv cache the
core populated. The package is `crypto_lab_offline_data` (distribution
`crypto-lab-offline-data`, version `0.1.0`) under `offline_data/src/`, for CPython
`>=3.12,<3.13` selected by `uv` from the user-local managed installs only.

### SQLite registration contract test (temporary database only)

`tests/integration/test_sqlite_dataset_registration.py` is the consumer test on the
registration side of the boundary. For each of the five committed golden families (the two
`ohlcv-csv/1` goldens under `tests/fixtures/candles/golden/` and the three SYNTHETIC
`binance-spot-kline-csv/1` goldens under `tests/fixtures/binance/golden/`) it strictly
re-parses `descriptor.json` and `partitions.json` through the core models, recomputes the
identity with the core's `dataset_metadata_hash`, registers the pair through the real
`crypto_lab.persistence.registries.SqliteDatasetRepository` into a fresh SQLite database
that the core's own `open_for_migration` and `apply_migrations` create under pytest's
`tmp_path`, commits, closes, reopens through `open_database` and reads the records back by
content hash (`get_by_hash`) and by ordinal (`list_partitions`). The read-back must equal
the parsed goldens typed field by field and as canonical JSON bytes, the ordinals must be
`0..n-1` with the partition IDs in the descriptor's order, re-registration of the identical
pair must succeed and leave one row per table, and two negative controls pin the structured
refusal (`CORE.INVARIANT_VIOLATION` with `table`, `operation` and `identity` details): a
descriptor whose `content_hash` is not its material metadata is refused before any row
exists, and a descriptor that differs only in `created_at_utc` (excluded from the hash) is
refused under the already registered hash with the original records unchanged.

The core enters only through the existing non-editable path dependency, pinned to the
accepted core source `main` `079395bec70f1deda406d0ca14b2d4bf79aaf063`; the test imports no
core test helper, no `sqlalchemy` module and no `crypto_lab.persistence.schema` name, and
counts rows with literal SQL on the repository's own connection. The placement follows the
delegated decision in section 1 of
`docs/superpowers/plans/2026-11-11-project-2-sqlite-dataset-registration-contract-plan.md`:
Workstream A keeps sole ownership of the shared core code, contracts and migrations; this
sub-project owns only the test and this explanation. The registration is temporary only:
every database lives under `tmp_path` and is closed in `finally`, all five families reuse
one dataset and one partition identifier so no two families share a database, no
application or persistent registry is opened, no partition `relative_path` is read, and no
production module, registration command or production registration authorization is
added. The focused command, from the repository root, is

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/invoke-offline-uv.ps1 pytest-focused -o addopts= tests/integration/test_sqlite_dataset_registration.py tests/integration/test_core_contract_roundtrip.py tests/safety/test_boundaries.py -q
```

and the sub-project's full gates are unchanged.

## Prerequisites

Same as the core: `uv` installed and a user-local uv-managed CPython 3.12
(`uv python find --managed-python --system --no-python-downloads 3.12`). This
sub-project downloads nothing; if the interpreter is missing, stop.

## Launcher

`offline_data/scripts/invoke-offline-uv.ps1` mirrors the core launcher
`scripts/invoke-uv.ps1`: exactly one resolvable `uv.exe`, invoked by its normalized
absolute path; `--no-config`, `--managed-python`, `--no-python-downloads` and
`--offline` on every profile; the project pinned with `--directory` and `--project` to
`offline_data/`; the same child-environment hygiene (`PYDANTIC_DISABLE_PLUGINS=__all__`
set unconditionally, the fixed uv, Python, virtual-environment, pytest, coverage and
mypy selection variables removed by name, no environment value ever read or printed);
caller-selected Python, scripts, tools, uv flags and external pytest paths or options
rejected. The profile set is closed. There is no acquiring (`lock-acquire`,
`sync-acquire`), `build`, schema, migration or command-line profile, and no profile can
reach the network. The launcher derives its root from its own location, so it behaves
identically from the repository root and from `offline_data/`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\offline_data\scripts\invoke-offline-uv.ps1 <profile> [arguments]
```

Operator-run environment profiles. They create or check the environment, dispatch
before any interpreter is resolved, and are run by the operator in this order on a
fresh checkout:

| Profile | uv command (after the fixed controls) | Purpose |
|---|---|---|
| `lock-resolve-offline` | `uv --offline lock` | Resolves `offline_data/uv.lock` from the local cache; the first proof of the environment |
| `lock-check` | `uv --offline lock --check` | Proves the committed lock matches `pyproject.toml` |
| `sync` | `uv --offline sync --frozen --no-build-isolation` | Creates `offline_data/.venv` from the frozen lock and builds the core wheel without isolation (hence `hatchling==1.31.0` in the dev group) |

Profiles a relay worker may run. Each resolves and validates
`offline_data\.venv\Scripts\python.exe` and proves it stays inside the sub-project
environment before running:

| Profile | Runs | Arguments |
|---|---|---|
| `pytest-focused` | pytest on explicit targets | `[-o addopts=] <tests/...> [<tests/...> ...] [-q]`; each target is spelled relative to `offline_data/` and must match `^tests/[A-Za-z0-9_./-]+(?:::[A-Za-z0-9_]+)?$`; no `..`, no absolute path, no other option; a bare `tests` is refused |
| `ruff-format-all` | `ruff format --check .` | none |
| `ruff-check-all` | `ruff check .` | none |
| `mypy-all` | `python -m mypy` (strict, `files = ["src", "tests"]`) | none |

`pytest-all` runs the whole suite with the configured addopts (branch coverage and the
floor below). It is used by the verify script.

## Verification

`offline_data/scripts/verify-offline.ps1` mirrors the core's `scripts/verify.ps1`. It
runs, each stage through the launcher, in order: `lock-check`, `sync`,
`ruff-format-all`, `ruff-check-all`, `mypy-all`, `pytest-all`, then `git diff --check`
scoped to `offline_data/`. It stops at the first non-zero exit and names the failed
stage.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\offline_data\scripts\verify-offline.ps1
```

The enforced branch-coverage floor is 98.61 percent: `--cov-fail-under=98.61` in the
pytest addopts and `fail_under = 98.61` with `precision = 2` in the coverage report
settings, so the comparison is made at two decimals rather than after rounding the total
to a whole percent. The plan names both the core's configured 90 percent floor and the
98.61 percent acceptance figure; this sub-project enforces 98.61.

The core's own `scripts/verify.ps1` keeps applying to every Project 2 task: its
`ruff-format-all` and `ruff-check-all` stages traverse `offline_data/` from the
repository root and apply this sub-project's nested `[tool.ruff]` configuration. Run the
sub-project verifier and the core verifier alone, never concurrently.

## Reporting boundaries

- **P2-B1 - Parquet.** The specification makes dataset partitions Parquet files. Parquet
  emission needs `pyarrow`, a prohibited dependency family that is not approved for
  acquisition anywhere. The declared policy for this slice: the partition container is
  an explicitly labelled interim NDJSON container; nothing names it a Parquet partition;
  every descriptor carries the limitation in `known_limitations` and every partition in
  `quality_observations`; and no interim container is ever registered in a persistent
  registry. Lifting P2-B1 is a separately authorized acquisition and a later task.
  `normalize.write_normalized_container` emits the interim container described under
  "Normalized container" below; `metadata.build_dataset_metadata` records the limitation
  text in every descriptor's `known_limitations` and every partition's
  `quality_observations` (see "Dataset metadata" below), and nothing here registers an
  interim container anywhere.
- **P2-B2 - offline lock resolution.** If `lock-resolve-offline`, `lock-check` or
  `sync` cannot be satisfied from the local uv cache, the exact missing distribution
  and the exact uv message are reported once as P2-B2 and nothing is acquired. P2-B2
  stops Task 0: the scaffold is not committed, no worker is dispatched and no product
  code is authored, because no executable route other than the launcher's pinned
  `offline_data/.venv` exists (no `uv run`, no system Python, no provisional runner) and
  nothing is faked. The one-time boundary report names the exact uv message and asks
  the owner how the clause to continue independently useful parsing and validation work
  is to be honoured.

## Input format

Two input formats are supported, each a separate, explicit identity selected with the
command's `--input-format` (default `ohlcv-csv/1`). The first slice's format is
`ohlcv-csv/1`, read by
`crypto_lab_offline_data.candle_csv.read_ohlcv_csv(path, *, ids, clock, max_rows, max_bytes)`;
the second slice's format, `binance-spot-kline-csv/1`, has its own subsection below and
reuses this reader's shared rules without changing them. Both readers are strict: every
violation below is a refusal, and nothing is truncated, converted or repaired.

- **Input path.** The path must be a readable regular file. A missing path, a
  directory, an unreadable file (for example one another process holds open without
  sharing), a reparse point (a junction or symbolic link is refused on its own
  attributes, never followed) or a bounded read that fails is
  `OFFLINE_DATA.INPUT_PATH` at line `0` with value length `0`; the path and its file
  name never enter the diagnostic, and no `OSError` escapes the reader. A regular file
  reached through a junction in an ancestor directory is not itself a reparse point and
  is read.
- **Encoding and line endings.** UTF-8 text without a byte order mark; LF or CRLF line
  endings; a missing final newline is accepted, a blank line inside the body is not. A
  carriage return is a line ending only when a line feed follows it: an unpaired
  carriage return (for example a final `\r` with no `\n` after it) stays in its line,
  which is then refused by the rule it violates, with the carriage return counted in
  the recorded length. Undecodable bytes are refused with `OFFLINE_DATA.CSV_ENCODING`,
  naming the line that holds the first undecodable byte and that line's byte length.
- **Header.** The first line is exactly `open_time_utc,open,high,low,close,volume`
  (case, order and field count included). Anything else, including an empty file, is
  `OFFLINE_DATA.CSV_HEADER` at line 1. A file holding only the header is
  `OFFLINE_DATA.EMPTY_SERIES` at line 2, the line at which the first data row was
  expected; `validate_series` returns the identical `Failure` for an empty row tuple.
- **Rows.** Exactly six comma-separated fields, no quoting, no surrounding whitespace.
  Any other field count, including a blank line, is `OFFLINE_DATA.CSV_ROW_SHAPE`.
- **`open_time_utc`.** `YYYY-MM-DDTHH:MM:SSZ`: seconds precision, literal uppercase
  `Z`, and a real calendar instant. Naive values, numeric offsets, fractional seconds,
  lowercase `z`, Unix epochs and impossible dates (`2024-02-30`, hour `24`) are
  `OFFLINE_DATA.CSV_TIMESTAMP`. Parsed values are timezone-aware UTC `datetime`s;
  nothing is converted.
- **`open`, `high`, `low`, `close`, `volume`.** A run of digits optionally followed by
  one point and a run of digits: no sign or leading `+`, no exponent, no bare `.5` or
  `5.`, no thousands separator, no `NaN` or `Infinity`, and at most the core's 256
  canonical characters. Values are `decimal.Decimal` built from the exact source text
  (`42000.10` keeps its trailing zero; `007.50` is the Decimal `7.50`); no float is
  ever constructed. A price of zero is refused because prices must be positive; a zero
  volume is accepted. Every violation is `OFFLINE_DATA.CSV_NUMBER`.
- **Size ceilings.** At most 1,048,576 data rows and 64 MiB per input by default
  (`max_rows`, `max_bytes`). The row ceiling is `OFFLINE_DATA.SIZE_CEILING` at the line
  of the first row beyond it. The byte ceiling is the same code at line `0`, meaning
  the whole input, after one bounded read that stops one byte past the ceiling, so its
  recorded value length is `max_bytes + 1`. A negative `max_bytes` is a ceiling no input
  can satisfy: it is the same refusal at line `0` with value length `0`, returned
  before the input path is inspected or opened, so no negative size ever reaches a read
  call and an absent path with a negative ceiling is the ceiling refusal.

Each refusal is one core `Failure` holding one core `Diagnostic` built by
`crypto_lab_offline_data.diagnostics.refusal`: severity `ERROR`, category
`SCHEMA_VALIDATION`, source component `crypto-lab-offline-data`, `retriable = false`, a
`message` naming the line and the rule only, and
`details = {"line": n, "rule": code, "value_length": k}`. The offending value never
enters a diagnostic: only its one-based line (`0` for the whole input) and its length in
characters (bytes for the encoding and byte-ceiling rules) are recorded. The diagnostic
identifier and timestamp come from the injected `IdProvider` and `Clock` protocols of
`crypto_lab_offline_data.providers` (production providers `Uuid4IdProvider` and
`SystemClock`); tests inject fixed values, so every diagnostic is deterministic.

The reader performs at most one bounded read of the input and writes nothing. Ordering,
the timeframe grid, missing and duplicate bars, price sanity across fields and the
normalized form (`format_decimal`) belong to the validation below, not to the reader.

**Provider faults (plan reading R7).** An injected provider whose value the core refuses
(a `diagnostic_id` that is not a lowercase canonical `diag_` UUID4, a `now_utc` that is
naive, carries a non-zero offset or is not a `datetime`) is a fault of the caller's
composition, not of the input: no core `Diagnostic` can be built from it, so no `Failure`
exists to return. Each provider value is validated when it is drawn, before any core
model is constructed from it and outside every handler that converts a data-dependent
core error, and a refused value raises
`crypto_lab_offline_data.diagnostics.ProviderContractError`. It derives from
`RuntimeError`, so no `ValueError` conversion at a boundary can swallow it; it names the
provider method (`method` attribute) and never carries the value, and the core error
that refused the value is not chained. It is raised by `refusal` and, through it, by
`read_ohlcv_csv`, `read_binance_kline_csv`, `validate_series`,
`write_normalized_container` and `raw_checksum`; all five draw their providers only when
they build a refusal, so a faulty provider is never observed on an accepted input or a
completed write. It is the only exception that crosses the sub-project's boundary:
neither the core `ValidationError`, nor an `OSError`, nor the `ValueError` of a path the
platform rejects escapes any of them.

### Binance Spot kline CSV (`binance-spot-kline-csv/1`)

`crypto_lab_offline_data.binance_kline_csv.read_binance_kline_csv(path, *, timestamp_unit,
ids, clock, max_rows, max_bytes)` reads one already extracted Binance Spot historical kline
CSV file as the user placed it on disk, for one representative instrument
(`BINANCE:BTC/USDT:SPOT`) and one supported timeframe, `1m`. It returns the same
`Success[tuple[CandleRow, ...]] | Failure` as the first reader, so validation, the container,
the raw checksum and the metadata consume its rows unchanged. The reader downloads nothing,
calls no API, reads no archive or `.CHECKSUM` file and repairs nothing.

**Documented and UNVERIFIED facts.** The format facts come from documentation only (the
`binance/binance-public-data` README, its "Microsecond update" commit, the Spot REST
market-data documentation and the Binance Vision Dataset Terms, retrieved 2026-11-10):
the twelve columns and their order, the microsecond timestamps for Spot data from
2025-01-01 (milliseconds before), the interval list and the archive checksum scheme. The
delimiter (the README renders its example row pipe-separated in a table), header presence,
line endings, a final newline, the `Ignore` value, exponent-free numerics and whether any
file mixes units are UNVERIFIED and decided conservatively: the reader refuses what
differs. No successful ingestion of an actual Binance archive is claimed; every fixture is
SYNTHETIC and labelled so by its `SYNTHETIC-` name.

**Timestamp unit.** `timestamp_unit` is `TimestampUnit.MILLISECONDS` (`milliseconds`) or
`TimestampUnit.MICROSECONDS` (`microseconds`), declared by the caller (the command's
`--timestamp-unit`) and applied to the whole file; the reader never guesses it. With the
divisor `1000` or `1000000`, the integer of each time field is first checked against the
window `1483228800 * divisor <= value < 4102444800 * divisor`, the epoch seconds of
`2017-01-01T00:00:00Z` (inclusive) and `2100-01-01T00:00:00Z` (exclusive); a value outside
it is `OFFLINE_DATA.TIMESTAMP_UNIT` at the row's line with the field's length. That is
exactly what a millisecond value declared as microseconds (a 1970 instant) or a
microsecond value declared as milliseconds (far beyond 2100) produces. Because the check
precedes construction, the instant is then built by integer arithmetic alone
(`divmod(value, divisor)`, a `timedelta` of whole seconds and microseconds from the epoch);
no float is used and no `OverflowError` or `ValueError` can arise. Between 2001 and 2286
millisecond values have 13 digits and microsecond values 16.

**Shared rules.** Input path, size ceilings, encoding and line endings are exactly the
`ohlcv-csv/1` rules above (`INPUT_PATH`, `SIZE_CEILING` by bytes and by rows,
`CSV_ENCODING`; UTF-8 without a BOM; LF or CRLF; a missing final newline accepted). A file
using another delimiter, another line ending or exponent notation is refused by the rule it
violates, never repaired.

**No header row.** The documented layout has none and header presence is UNVERIFIED, so
the reader accepts none: every line is a data row. The line-1 rule comes first and applies
to line 1 only: a first line whose first comma-separated field is not an unsigned decimal
integer of 1 to 20 digits (a blank line, a documented-column-names header, a pipe-delimited
line) is `OFFLINE_DATA.CSV_HEADER` at line 1 with the line's length. Once that rule passes,
every line, line 1 included, is parsed by the row rules below in order, so a wrong-unit
value on line 1 is `TIMESTAMP_UNIT` at line 1. An empty file is `OFFLINE_DATA.EMPTY_SERIES`
at line 1, the line at which the first data row was expected.

**Rows.** Exactly twelve comma-separated fields, no quoting; anything else, a blank line
included, is `OFFLINE_DATA.CSV_ROW_SHAPE` with the line's length. Rules apply per row in
field order, so a row that breaks two rules is refused by the first:

| Field | Binance column | Grammar | Refusal | Mapped to |
|---|---|---|---|---|
| 1 | Open time | unsigned decimal integer `[0-9]{1,20}` in the declared unit, inside the window | `CSV_TIMESTAMP`; `TIMESTAMP_UNIT` | `CandleRow.open_time_utc` |
| 2 | Open | the `ohlcv-csv/1` number grammar, positive | `CSV_NUMBER` | `open` |
| 3 | High | same, positive | `CSV_NUMBER` | `high` |
| 4 | Low | same, positive | `CSV_NUMBER` | `low` |
| 5 | Close | same, positive | `CSV_NUMBER` | `close` |
| 6 | Volume (base asset) | the number grammar | `CSV_NUMBER` | `volume` |
| 7 | Close time | `[0-9]{1,20}` in the declared unit, inside the window, strictly greater than the open time | `CSV_TIMESTAMP`; `TIMESTAMP_UNIT`; `CSV_TIMESTAMP` with the close field's length | checked, not retained |
| 8 | Quote asset volume | the number grammar | `CSV_NUMBER` | checked, not retained |
| 9 | Number of trades | unsigned decimal integer `[0-9]+` within the canonical bound | `CSV_NUMBER` | checked, not retained |
| 10 | Taker buy base asset volume | the number grammar | `CSV_NUMBER` | checked, not retained |
| 11 | Taker buy quote asset volume | the number grammar | `CSV_NUMBER` | checked, not retained |
| 12 | Ignore | any text without a comma; not interpreted (its value is UNVERIFIED) | none | dropped |

Fields 2 to 6, 8, 10 and 11 use the slice-1 `_parse_number` rule (exact `Decimal`, the
core's 256-character canonical bound, no sign, no exponent, no whitespace; trailing zeros
such as `4.15070000` are kept and canonicalized only in the normalized container). A time
field that is not `[0-9]{1,20}` is `CSV_TIMESTAMP` with the field's length, a longer digit
run included: no `int()` is ever applied to an unbounded token and the interpreter's
integer-string digit limit is never reached (the tests prove the 20-digit bound, a 21-digit
token and a 4400-digit token). Because field 12 is not interpreted, a lone trailing carriage
return on the final line lands in it and the row is accepted; a file of CR-only line
endings is one line of too many fields, the `CSV_ROW_SHAPE` refusal. The relation shown by
the documentation's example row (close time = open time + interval - 1 unit) is not
enforced because the reader checks no timeframe: grid, spacing, ordering, gaps and
duplicates stay the `validate_series` rules on `open_time_utc`, so a file of a coarser
interval declared `--timeframe 1m` surfaces as missing intervals and
`VALID_WITH_WARNINGS`, a reversed `high`/`low` as `PRICE_SANITY`, a decreasing open time
as `ORDERING` and an off-grid open time as `TIMEFRAME_GRID`.

**Refusals.** The closed set gains one member, `OFFLINE_DATA.TIMESTAMP_UNIT`, appended
after `METADATA_FIELD` (fifteen codes). The reader emits:

| Code | When | `line`, `value_length` |
|---|---|---|
| `OFFLINE_DATA.INPUT_PATH`, `OFFLINE_DATA.SIZE_CEILING` (by bytes), `OFFLINE_DATA.CSV_ENCODING` | the shared rules above | as for `ohlcv-csv/1` (`line` 0 is used by this reader only through these shared paths) |
| `OFFLINE_DATA.SIZE_CEILING` (by rows) | the first row beyond `max_rows` | the row's line, the line's length |
| `OFFLINE_DATA.EMPTY_SERIES` | an empty file | 1, 0 |
| `OFFLINE_DATA.CSV_HEADER` | line 1 whose first field is not 1 to 20 digits | 1, the line's length |
| `OFFLINE_DATA.CSV_ROW_SHAPE` | a line without exactly twelve fields | the line, its length |
| `OFFLINE_DATA.CSV_TIMESTAMP` | a time field outside `[0-9]{1,20}`; a close time not after the open time | the line, the field's length |
| `OFFLINE_DATA.TIMESTAMP_UNIT` | a time field outside the window in the declared unit | the line, the field's length |
| `OFFLINE_DATA.CSV_NUMBER` | a numeric field outside its grammar (zero or signed prices included) | the line, the field's length |

Every diagnostic names the line, the rule and the length only, never the value (section
5.4 of the first-slice plan); the `diag_` identifier is drawn once per refusal and nothing
is drawn on success; a refused provider value raises `ProviderContractError`.

**Limitations and terms.** Fields 7 to 12 are validated for shape and not retained; every
`binance-spot-kline-csv/1` run records that fact as the P2-B3 limitation beside P2-B1 (see
"Interim format and pending obligations" and "Source terms" below). Non-goals of this
slice: futures or margin klines, every Binance interval other than `1m` for this format,
zip archives and `.CHECKSUM` files, header rows, multi-file concatenation.

## Validation

`crypto_lab_offline_data.validation.validate_series(rows, *, timeframe, ids, clock)`
applies the plan's section 4 rules to the rows the reader accepted and returns either a
`Success[ValidatedSeries]` or one refusal `Failure` built by `refusal`. Every row is
kept in input order; nothing is interpolated, dropped or de-duplicated.

`ValidatedSeries` carries `rows`, `missing_intervals` (core `TimeInterval` values),
`duplicate_intervals` (core `DuplicateInterval` values), `observations` (partition
quality observation texts), `start_utc`, `end_utc` and `row_count`.

Whole-input rules, in order:

- **Timeframe.** Exactly `1m`, `5m`, `15m`, `1h`, `4h` or `1d`
  (`SUPPORTED_TIMEFRAME_SECONDS`). Any other value, including the core grammar's `1s` and
  `1w`, is `OFFLINE_DATA.TIMEFRAME_GRID` at line `0` with the argument's length as its
  `value_length` and never the value. Line `0` denotes a refusal of the whole input or of
  an argument (`INPUT_PATH`, `SIZE_CEILING` by bytes, `OUTPUT_DIRECTORY`, `METADATA_FIELD`,
  and `TIMEFRAME_GRID` for an unsupported timeframe argument, whose `value_length` is the
  argument's length); every other refusal names the one-based line.
- **Empty series.** Zero rows is `OFFLINE_DATA.EMPTY_SERIES` at line `2` with value
  length `0`: field for field the same `Failure` the reader returns for a header-only
  file, so Task 1 and Task 2 pin one answer.

Per-row rules, in input order and in this order within a row, so a row that breaks two
rules is refused by the first. The refusal names the row's one-based line and the length
of the offending value in its canonical text, never the value:

| Order | Rule | Code | Offending value and recorded length |
|---|---|---|---|
| 1 | `open_time_utc` is timezone-aware UTC (a zero-offset `tzinfo` counts as UTC) | `OFFLINE_DATA.CSV_TIMESTAMP` | the open time, `len(isoformat())` (`19` naive, `25` with an offset) |
| 2 | `open_time_utc` sits on the grid: `(open_time - epoch) % step == 0` | `OFFLINE_DATA.TIMEFRAME_GRID` | the open time, `len(format_utc(...))` (`20`; `27` with microseconds) |
| 3 | each of `open`, `high`, `low`, `close`, `volume` has a canonical `format_decimal` form (finite, not negative zero, within 256 characters) | `OFFLINE_DATA.CSV_NUMBER` | the value, `len(str(value))` |
| 4 | `open`, `high`, `low`, `close` are positive, checked in that order | `OFFLINE_DATA.PRICE_SANITY` | the first non-positive price, canonical length |
| 5 | `high >= low` | `OFFLINE_DATA.PRICE_SANITY` | `high`, canonical length |
| 6 | `low <= open <= high`, then `low <= close <= high` | `OFFLINE_DATA.PRICE_SANITY` | `open` or `close`, canonical length |
| 7 | `volume >= 0` | `OFFLINE_DATA.VOLUME` | `volume`, canonical length |
| 8 | `open_time_utc` does not decrease against the previous row | `OFFLINE_DATA.ORDERING` | the open time, `len(format_utc(...))` |

Rule 3 concerns directly constructed rows only: the reader's grammar admits no such
value, and the rule exists so that the core `ValueError` behind `format_decimal` is
converted at this boundary like every other data-dependent core error.

**`CSV_NUMBER` versus `PRICE_SANITY`.** The reader refuses a signed or zero price as
`OFFLINE_DATA.CSV_NUMBER` (section 3: the number grammar has no sign, and a price must be
positive), so a fixture such as `invalid/negative-price.csv` never reaches the validator;
its test pins the reader's refusal at line `3` with value length `9`. The validator's
`PRICE_SANITY` rule covers what the reader cannot see, the relationship between the four
prices of one row (`invalid/high-below-low.csv` passes the reader and is refused at line
`3` with value length `8`, the length of `high`) and, for directly constructed rows, the
positivity rules; the `VOLUME` rule is exercised with directly constructed rows for the
same reason.

Quality facts, recorded and never repaired:

- **Duplicates.** Equal consecutive open times form one group; every row of the group
  is kept and one `DuplicateInterval(start_utc=open_time, end_utc=open_time + step,
  duplicate_count=n)` with `n >= 2` is recorded. The rows of a group are compared as
  `Decimal` values (`42000.50` and `42000.5` agree, as their normalized lines do); when
  any row of any group differs from its group's first row, `observations` carries the
  one text `DIFFERING_DUPLICATE_OBSERVATION`, which names no value.
- **Missing bars.** A jump of more than one step from a group's open time to the next
  present open time records `TimeInterval(start_utc=open_time + step, end_utc=next open
  time)`: from the first missing open time to the next present one, half-open.
- **Interval (reading R5).** `start_utc` is the first open time and `end_utc` the last
  open time plus one step.
- **Row count.** `row_count` is the number of rows kept, duplicates included, so it
  equals the container's line count; the distinct count follows from
  `duplicate_intervals`.

Both interval tuples are in time order and unique, as the core descriptor requires. The
validation status (reading R4) is decided by `metadata.build_dataset_metadata` from these
facts: no missing and no duplicate interval is `VALID`; either is `VALID_WITH_WARNINGS`; a
refusal emits nothing.

The committed `btcusdt-1m-gaps-duplicates.valid.csv` holds 60 rows and 58 distinct open
times from `2024-01-01T00:00:00Z` to `2024-01-01T01:00:00Z`: minutes 20 to 22 are missing
(`TimeInterval` from `00:20` to `00:23`), minute 30 appears twice with identical values
and minute 45 twice with a differing close and volume (two `DuplicateInterval` records
with `duplicate_count` 2 and one observation); `end_utc` is `2024-01-01T01:01:00Z`.

## Normalized container (interim, P2-B1)

`crypto_lab_offline_data.normalize.write_normalized_container(series, path, *, ids, clock)`
writes the plan's section 5.2 container `normalized-ndjson/0.1.0` (`CONTAINER_FORMAT`; row
schema `column_schema_version` `0.1.0`, `COLUMN_SCHEMA_VERSION`) and returns a
`Success[NormalizedContainer]` carrying `bytes_written`, `content_hash`,
`normalized_checksum` and `row_count`, or one refusal `Failure` built by `refusal`.

- One line per kept row, in input order, duplicates included, so `row_count` equals an
  independent line count.
- Each line is the core's canonical JSON of the row: sorted keys `close`, `high`, `low`,
  `open`, `open_time_utc`, `volume`; compact separators; UTF-8; the five numbers as
  `format_decimal` strings (`42000.00` becomes `42000`, `100.0` becomes `100`); the open
  time in the core UTC form `YYYY-MM-DDTHH:MM:SSZ`. The first line of the clean fixture's
  container:

  ```text
  {"close":"42000.5","high":"42001","low":"41999","open":"42000","open_time_utc":"2024-01-01T00:00:00Z","volume":"100"}
  ```

- Every line ends with `\n`, so the file ends with a final newline and holds no `\r`.
- `normalized_checksum` and `content_hash` are both the lowercase SHA-256 hex digest of
  the whole container's bytes (plan section 1.5: equal by construction in this slice).
- Writing the same validated series into two fresh directories yields identical bytes,
  checksums and `NormalizedContainer` values; a second write into the same directory is
  the refusal below, never a replacement.

The writer is the one place in the package that writes, and the boundary guards pin it
to exactly one `path.open("xb")`, one `write` call and one `path.unlink()` on the same
path inside `write_normalized_container`:

- It writes exactly one file, the caller's explicit `path`, through an exclusive create,
  and never overwrites or follows. Before it opens anything it inspects the entry at
  `path` itself without following it (`lstat`, never `exists()` or a resolution through
  a link): any existing entry there (a file, a directory, or a reparse point whether or
  not its target exists) is refused on its own attributes and never replaced, followed
  or removed. A dangling junction or symbolic link at `path` is therefore refused before
  the create could follow it, so its missing target is never created, inside or outside
  the output directory. Only the platform's "no such entry" answer lets the create
  proceed; an inspection of the entry that fails for any other reason is the same
  refusal with nothing opened.
- It creates no directory, and it inspects the destination's directory without
  following it, before the destination's own entry and before it opens anything: a
  missing directory, a directory that is itself a reparse point (a junction or symbolic
  link, refused on its own attributes), a directory that is a file, or one in which the
  exclusive create is denied is refused with nothing opened or created. A regular
  directory reached through a junction in an ancestor is not itself a reparse point and
  is used, the reader's rule for its input. The `normalize` command creates its `--output`
  directory immediately before this write.
- Every such case, and a path the platform rejects outright (an embedded NUL), is the
  refusal `OFFLINE_DATA.OUTPUT_DIRECTORY` at line `0` with value length `0`; the path and
  its file name never enter the diagnostic, and no `OSError` or path `ValueError`
  escapes the writer. The writer draws its providers only for that refusal. A
  pre-existing `part-0000.ndjson` under `--output` is therefore this refusal rather than
  a replacement.
- The writer owns the destination only once the exclusive create has returned. If the
  write, or the close that completes it, then fails, the partial file it created is
  removed before anything else happens and the same refusal is returned; a removal that
  itself fails still returns that refusal, with nothing crossing. A failure before the
  create owns nothing, so a pre-existing entry is never removed.

## Raw checksum

`crypto_lab_offline_data.normalize.raw_checksum(path, *, max_bytes, ids, clock)` returns a
`Success[RawChecksum]` carrying `sha256`, the lowercase SHA-256 hex digest of the input's
exact bytes, and `byte_count`, or one refusal `Failure`. It is the pipeline's one
deliberate second read of the input: the reader's single bounded read yields rows, not
bytes, and the raw text's exact digits (`42000.00`, `100.0`) survive only through this
digest, since the container carries the normalized form. It reuses the reader's
bounded-read helper by import, so its refusals are the reader's: a negative `max_bytes`
is `OFFLINE_DATA.SIZE_CEILING` at line `0` with value length `0`, returned before the
path is inspected; a missing path, a directory, an unreadable file, a reparse point, a
failing read or a path the platform rejects is `OFFLINE_DATA.INPUT_PATH` at line `0` with
value length `0`, the path never recorded; an input over the ceiling is
`OFFLINE_DATA.SIZE_CEILING` at line `0` with value length `max_bytes + 1`. `max_bytes` has
no default: the caller passes the ceiling it gave the reader, so both reads of one input
are bounded alike. `metadata.build_dataset_metadata` records the digest as the
descriptor's `source_hash` and `raw_checksums` entry and the partition's `raw_checksum`.

## Dataset metadata

`crypto_lab_offline_data.metadata.build_dataset_metadata(series, container, raw, *,
instrument, timeframe, source, input_name, ids, clock,
source_format=InputFormat.OHLCV_CSV_1)` turns a `ValidatedSeries`, the
`NormalizedContainer` of its write and the `RawChecksum` of the input into a
`Success[DatasetBundle]` (`descriptor`: the core `DatasetDescriptor`; `partitions`: the one
core `DatasetPartition`) or one refusal `Failure`. `instrument` is the core `InstrumentRef`
the command builds with the core's `parse_instrument_id`; `source` is the command's
`--source` text; `input_name` is the input file's name; `source_format` is the
`InputFormat` (`StrEnum`: `OHLCV_CSV_1 = "ohlcv-csv/1"`,
`BINANCE_SPOT_KLINE_CSV_1 = "binance-spot-kline-csv/1"`) whose identity the literal table
`SOURCE_IDENTITIES` maps to the provenance pair (`("ohlcv-csv", "1.0.0")`, equal to the
retained `SOURCE_NAME` and `SOURCE_VERSION`; `("binance-spot-kline-csv", "1.0.0")`). Every
existing call keeps the default and emits bytes identical to the first slice's. Every
field follows plan section 5.1:

| Descriptor field | Value |
|---|---|
| `schema_version` | `1.0.0` |
| `dataset_id` | one `ds_` draw of the injected `IdProvider` |
| `source` | `--source` (default `local-fixture`), 1 to 1024 characters |
| `venue`, `instrument` | the venue of, and the whole, `InstrumentRef` parsed from `--instrument` (`VENUE:BASE/QUOTE:MARKET`) |
| `data_type` | `OHLCV` |
| `timeframe` | `--timeframe`, one of the six supported values |
| `start_utc`, `end_utc` | the validated series' half-open bounds |
| `original_timezone` | `UTC` (the input contract admits only `Z`) |
| `normalized_to_utc` | `true` |
| `imported_at_utc`, `created_at_utc` | one `now_utc` draw of the injected `Clock`, used for both |
| `raw_source_provenance` | one entry: `source_name` and `source_version` from `SOURCE_IDENTITIES[source_format]` (`ohlcv-csv`, `1.0.0` by default; `binance-spot-kline-csv`, `1.0.0` for the Binance format), `source_record` the input file name, `source_hash` the raw checksum |
| `normalization_implementation`, `normalization_version` | `crypto-lab-offline-data`, `0.1.0` |
| `validation_status` | `VALID` without missing or duplicate intervals, else `VALID_WITH_WARNINGS` (reading R4); `INVALID` is never emitted because a refused input emits nothing |
| `partition_ids` | the one `part_` draw |
| `missing_intervals`, `duplicate_intervals` | the validated series' tuples (sorted, unique) |
| `diagnostic_ids` | empty |
| `raw_checksums`, `normalized_checksums` | one entry each: the raw checksum and the container's SHA-256 |
| `column_schema_version` | `0.1.0` |
| `known_limitations` | `interim container normalized-ndjson/0.1.0; Parquet partition emission requires the pyarrow acquisition (P2-B1)`; for `binance-spot-kline-csv/1` runs also the P2-B3 text below, the tuple sorted (the core requires sorted collections, so the `P2-B3:` text lands first) |
| `content_hash` | the construction below |

| Partition field | Value |
|---|---|
| `schema_version`, `partition_id`, `dataset_id`, `ordinal` | `1.0.0`, the `part_` draw, the descriptor's id, `0` |
| `relative_path` | `datasets/<dataset_id>/part-0000.ndjson` (registry-relative POSIX, never a filesystem path) |
| `content_hash`, `normalized_checksum` | both the SHA-256 of the container bytes (equal by construction in this slice) |
| `row_count` | the container's line count, duplicates included |
| `start_utc`, `end_utc`, `raw_checksum`, `column_schema_version`, `raw_source_provenance` | the descriptor's |
| `quality_observations` | the P2-B1 limitation text above (and the P2-B3 text for `binance-spot-kline-csv/1` runs), plus `DIFFERING_DUPLICATE_OBSERVATION` when the series raised it, sorted |

**Content hash (plan section 5.4).** The descriptor is first built with a placeholder
`content_hash` of sixty-four zeros, `dataset_metadata_hash(descriptor, partitions)` is
computed by the core (its profile `dataset-metadata/v1` excludes `content_hash`,
`created_at_utc`, `dataset_id`, `diagnostic_ids`, `imported_at_utc` and `partition_ids`,
and the partition's `dataset_id`, `partition_id` and `relative_path`), the descriptor is
re-created through `DatasetDescriptor.model_validate` over its dump with the digest in
place, and `validate_dataset_identity` is called. `model_copy(update=...)` is never used,
so every value passes the core validators. Because the identifiers and instants are
excluded, the hash of a fixture is the same under any providers: the two committed golden
hashes are properties of the fixtures, not of the test doubles.

**Boundary.** An unsupported `timeframe` is `OFFLINE_DATA.TIMEFRAME_GRID` at line `0` with
the argument's length, decided before any provider is drawn. The `ds_` and `part_`
identifiers and the instant are drawn and validated before any core model is built and
outside every handler; a value the core refuses raises `ProviderContractError` (reading
R7), and the `diag_` identifier is drawn only for a refusal, after the handler below. A
core model refusing a value the function records from its arguments or its consumed
products is the refusal `OFFLINE_DATA.METADATA_FIELD` (plan section 5.4): a `source` or
`input_name` outside the core's `BoundedText` bounds of 1 to 1024 characters; a
`content_hash`, `normalized_checksum` or `sha256` of the consumed `NormalizedContainer` or
`RawChecksum` that is not the core's `Sha256` form of 64 lowercase hexadecimal characters;
and any other recorded field of the consumed `ValidatedSeries`, `NormalizedContainer` or
`RawChecksum` (`row_count`, `start_utc`, `end_utc`, the interval tuples, the observations)
the core refuses. It is emitted at line `0` with value length `0` because the one handler
that converts the core's `ValueError` covers every recorded field and does not inspect the
core's error, so it attributes no length; the message names the rule and never the value.
It is never emitted for `INPUT_PATH`'s cases and never replaced by `INPUT_PATH`, and it is
not reachable through the command, whose `--source` is bounded at argument parsing, whose
`input_name` is the name of the regular file the reader opened and whose digests are the
hashing functions' own; the command maps it like any refusal, exit `1`. No core
`ValidationError` escapes. On success the function draws `dataset_id`, `partition_id` and
`now_utc` exactly once each; on a `METADATA_FIELD` refusal it draws those three first and
the `diag_` identifier and the diagnostic's instant after the handler.

## Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\offline_data\scripts\invoke-offline-uv.ps1 <profile> ...
```

is the launcher for tooling; the product command itself is the package's module entry
point, run by the sub-project's interpreter as

```text
python -m crypto_lab_offline_data normalize --input <file> --output <directory> --instrument VENUE:BASE/QUOTE:MARKET --timeframe <tf> [--source <text>] [--input-format <format>] [--timestamp-unit <unit>]
```

(`crypto_lab_offline_data.cli.normalize_command(argv, *, ids, clock) -> int` is the same
command with injected providers; `argv=None` reads the process arguments, as the entry
point does with `Uuid4IdProvider` and `SystemClock`). `--input-format` has the closed
choices `ohlcv-csv/1` (default) and `binance-spot-kline-csv/1`; `--timestamp-unit` has the
closed choices `milliseconds` and `microseconds`. `--timestamp-unit` is required with
`binance-spot-kline-csv/1` and refused with `ohlcv-csv/1`, and `--timeframe` must be `1m`
with `binance-spot-kline-csv/1`, the only timeframe that format supports (`ohlcv-csv/1`
keeps its six timeframes); each violation, and a value outside either closed set, is an
argparse error (exit `2`) whose message names the options and the admitted literals only,
never the given value. The command writes three files into
`--output`: `part-0000.ndjson` (the interim container), `descriptor.json` and
`partitions.json` (the canonical JSON bytes of the `DatasetDescriptor` and of the JSON
array of `DatasetPartition` models, no trailing newline). The sequence is the plan's: read
(through the selected reader, `read_ohlcv_csv` or `read_binance_kline_csv`), validate
(`validate_series`), `raw_checksum`, then one draw of each
provider value (`dataset_id`, `partition_id`, `diagnostic_id`, `now_utc`, in that order,
each validated when drawn) snapshotted into fixed providers, then `--output` inspected and
created immediately before the first write, then the container, the metadata (with the
selected format as `source_format`) and the two
JSON files. Everything after the snapshot receives the fixed providers, so nothing is drawn
after the first write and every later refusal carries the reserved `diag_` identifier and
instant.

| Exit | Meaning |
|---|---|
| `0` | success; nothing is printed (also argparse's own exit for `--help`, which prints the usage text) |
| `1` | refusal: the `Failure` of any step, `OFFLINE_DATA.INPUT_PATH`, `OFFLINE_DATA.METADATA_FIELD` (mapped like any refusal, though unreachable through the command, see "Dataset metadata") and `OFFLINE_DATA.OUTPUT_DIRECTORY` included; the `Failure` is printed as one canonical JSON line |
| `2` | argument parsing only (argparse's own exit): a missing or unknown argument, an `--instrument` the core helper cannot parse, a `--source` outside 1 to 1024 characters, an `--input-format` or `--timestamp-unit` outside its closed choices, a `--timestamp-unit` given with `ohlcv-csv/1` or missing with `binance-spot-kline-csv/1`, or a `--timeframe` other than `1m` with `binance-spot-kline-csv/1`, each with a message that never echoes the value. For `ohlcv-csv/1` an unsupported `--timeframe` is not an argument error: it is `validate_series`'s `TIMEFRAME_GRID` refusal, exit `1` |
| `3` | provider fault: `ProviderContractError` from any step; its message, naming the provider method only, is printed |

The printed lines name no value and no path. They go to standard output because the
sub-project's boundary guards admit no `sys` import and therefore no standard-error handle.

**`--output`.** The path is taken as given (a relative path is relative to the working
directory) and inspected on its own entry without following it: an absent path is created
with one `mkdir()`, so its parent must exist (a missing parent is "cannot be created"); an
existing regular directory is used when it holds none of the three output names (any entry
at one of those names, a dangling reparse point included, is refused); a file, a reparse
point (junction or symbolic link, refused on its own attributes), a path that cannot be
created and a path the platform rejects are the `OUTPUT_DIRECTORY` refusal, exit `1`,
drawn from the snapshot. Nothing is written outside `--output`, unrelated entries inside it
are never touched, and nothing is ever overwritten: a second run into the same directory is
the refusal, while two runs into two fresh directories produce identical bytes.

**Cleanup.** The command records each file as soon as its exclusive create has returned
and, when a later step fails (a metadata refusal, a failed `descriptor.json` or
`partitions.json` write) or a provider fault is raised, removes those files in reverse
order, the completed container included, attempting each removal even after one fails; a
removal that itself fails changes nothing: the outcome in flight (the refusal, or a provider
fault's exit `3`) stands and nothing crosses. A partial container is the writer's own to
remove. Exits `1`, `2` and `3` therefore leave under `--output` nothing the command created
beyond the directory itself and any created file whose removal failed; the directory, when
the command created it, is never removed and is empty when every removal succeeded;
pre-existing entries are never touched.

**Goldens and the consumer check.** `tests/fixtures/candles/golden/` holds, for each valid
fixture, `<stem>.descriptor.json`, `<stem>.partitions.json` and `<stem>.content_hash.txt`
(the hash and one line feed), captured once from the first green run with the fixed test
identifiers and clock and committed as a review oracle; there is no regeneration command and
no update option. `tests/integration/test_core_contract_roundtrip.py` compares the command's
output with them byte for byte and, independently of the hash files, re-parses both golden
JSON documents through the core models in strict JSON mode, recomputes the identity with the
core's `dataset_metadata_hash`, checks it with `validate_dataset_identity` and ties the
partition's `content_hash` and `raw_checksum` to the container and fixture bytes. Golden
hashes: clean `9377a6d4...`, gaps-duplicates `41acb380...` (full digests in the files).
`tests/fixtures/binance/golden/` holds the same three files for each of the three SYNTHETIC
Binance fixtures (nine files), captured once with `--input-format binance-spot-kline-csv/1`,
the fixture's unit, `--timeframe 1m` and `--source synthetic-binance-fixture`, pinned byte
for byte by `tests/unit/test_cli.py` and re-parsed, recomputed and shown deterministic
across two fresh directories by the integration module. Golden hashes:
`SYNTHETIC-BTCUSDT-1m-2024-12-31-ms` `932499c6...`, `SYNTHETIC-BTCUSDT-1m-2025-01-01-us`
`820dc27a...`, `SYNTHETIC-BTCUSDT-1m-gaps-duplicates-us` `903a55b2...`.

## Interim format and pending obligations

- The partition container is `normalized-ndjson/0.1.0`, an interim format (P2-B1). It is
  not a Parquet partition and is never called one; every descriptor and partition says so.
- **P2-B3.** Every `binance-spot-kline-csv/1` descriptor and partition also carries the
  literal `P2-B3: binance-spot-kline-csv/1 fields 7 to 12 (close time, quote asset volume,
  number of trades, taker buy volumes, ignore) are validated for shape and not retained;
  synthetic fixtures only, no real Binance archive ingested` (`metadata.P2_B3_LIMITATION`,
  within the core's `BoundedText` bound) in `known_limitations` and `quality_observations`,
  each tuple sorted so the `P2-B3:` text precedes the lowercase P2-B1 text. `ohlcv-csv/1`
  outputs are byte-identical to the first slice's and carry P2-B1 alone.
- No interim container is registered in a persistent core dataset registry. Registration
  is exercised only as a temporary-database contract test through
  `SqliteDatasetRepository`: `tests/integration/test_sqlite_dataset_registration.py`
  registers each committed golden into a fresh SQLite database under pytest's `tmp_path`
  against the accepted core source `main` `079395bec70f1deda406d0ca14b2d4bf79aaf063`,
  reached only through the existing path dependency, and reads it back by hash and
  ordinal; its focused command is `pytest-focused -o addopts=
  tests/integration/test_sqlite_dataset_registration.py
  tests/integration/test_core_contract_roundtrip.py tests/safety/test_boundaries.py -q`
  through `offline_data/scripts/invoke-offline-uv.ps1` (spelled out in full in "SQLite
  registration contract test (temporary database only)" above). It is placed here under
  the delegated decision in section 1 of
  `docs/superpowers/plans/2026-11-11-project-2-sqlite-dataset-registration-contract-plan.md`
  (Workstream A keeps the shared core contract). The registration limit is temporary
  only: no application or persistent registry is opened and no registration command or
  production registration is added; finalization through the artifact finalizer follows
  the Stage 9 merge and stays pending here.
- Two input formats, one instrument, one partition per dataset; `binance-spot-kline-csv/1`
  supports `1m` only; the real-source adapter and any claim of real-source execution wait
  for the authorized source verification.
- The command prints to standard output only, creates no parent directory for `--output`
  and does not remove a directory it created; `--instrument`, `--source`, `--input-format`,
  `--timestamp-unit` and their couplings are argument refusals (exit `2`), the one argument
  refusal with a diagnostic is `--timeframe` for `ohlcv-csv/1`.

## Source terms

The Binance Vision Dataset Terms (v1.0, `TERMS_AND_CONDITIONS.md`, as recorded in the
second-slice plan) license the published historical data under CC BY-NC-SA 4.0:
non-commercial, attribution, no redistribution of derivative data feeds; the permitted uses
include algorithmic historical backtesting for purely personal non-production research.
This tool reads user-provided extracted files for personal, non-production research,
downloads nothing, redistributes nothing and ships only SYNTHETIC fixtures; the user
remains responsible for complying with the terms of any file they place on disk.

## Safety scope

Unchanged from the core: personal, local-only, research only; no real-money orders, no
credentials or API keys, no leverage, futures, margin or shorting, no implicit network
access, no Docker, cloud or server deployment.
