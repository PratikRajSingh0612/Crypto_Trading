# Project 2, second slice: the `binance-spot-kline-csv/1` reader (compact just-in-time plan)

**Status.** Revision 1, authored by the controller session on 2026-11-10 under the owner assignment
"PARALLEL ASSIGNMENT: PROJECT 2 OFFLINE BINANCE CANDLE READER" (2026-11-10), which authorizes one compact
just-in-time plan accepted through the existing delegated acceptance process (independent review plus the
advisor) without another routine owner approval. Base: the accepted Project 2 slice-1 checkpoint, commit
`3a47d4c9ecdcd6967a670246144ea7ee6c999ed4` (P2-T3 published; token `P2_SLICE1_PLAN_COMPLETE`), on the new
branch `project-2-binance-kline-reader`. Slice 1 stays accepted and closed; nothing here reopens it.

**Authority and sources.** The slice-1 plan (`2026-11-09-project-2-offline-data-first-slice-implementation-plan.md`,
revision 22) and the sub-project README define the pipeline this slice extends; its readings R1 to R7 and its
section 5.4 diagnostics contract stay binding. Format facts come from documentation only, retrieved
2026-11-10 (no archive was downloaded, no API called): the `binance/binance-public-data` README (column layout
under "SPOT / Klines" with the example row `1735689600000000|4.15070000|...|1735693199999999|...|0`, the note
"The timestamp for SPOT Data from January 1st 2025 onwards will be in microseconds", the interval list, the
CHECKSUM paragraph), its commit `de6bdec` "Microsecond update" (examples changed from millisecond values
`1601510340000`/`1601510399999`), the Spot REST market-data documentation (the same twelve kline fields), and
the Binance Vision Dataset Terms v1.0 (`TERMS_AND_CONDITIONS.md`; CC BY-NC-SA 4.0, non-commercial; permitted
uses include "algorithmic historical backtesting for purely personal non-production research"). Facts the
documentation does not establish are marked UNVERIFIED below and are decided conservatively.

## 1. Scope and non-goals

- One source format, `binance-spot-kline-csv/1`: an already-extracted Binance Spot historical kline CSV
  file as the user places it on disk. One representative instrument, `BINANCE:BTC/USDT:SPOT`, one supported
  timeframe, `1m`, in the fixtures and goldens; the reader itself is timeframe-agnostic and the command
  accepts the six supported timeframes unchanged.
- The format is a separate, explicit identity. `ohlcv-csv/1` is not broadened: its reader, grammar, fixtures,
  goldens and refusals are untouched, and the command's default input format stays `ohlcv-csv/1`.
- No downloading, no exchange API, no dependency acquisition, no installation, no new dependency. The
  sub-project's environment, lock, launcher and verify script are unchanged.
- The interim limitation P2-B1 stands: the output is the `normalized-ndjson/0.1.0` container with
  `descriptor.json` and `partitions.json`; no Parquet, no persistent registration, no artifact-finalizer
  integration. A second limitation literal, P2-B2, records what this format drops (section 2.6).
- Fixtures are SYNTHETIC and labelled so; passing them establishes no successful ingestion of an actual
  Binance archive. No claim of real-source execution is made without separately authorized evidence.
- Non-goals: futures or margin klines (different timestamp notes and `Ignore` values), the `1s`, `3m`, `30m`,
  `2h`, `6h`, `8h`, `12h`, `3d`, `1w`, `1mo` intervals (the pipeline supports six timeframes), zip archives
  and `.CHECKSUM` files (the reader takes the extracted CSV; the archive checksum is not modelled), header
  rows (section 2.2), multi-file concatenation.

## 2. The `binance-spot-kline-csv/1` format

### 2.1 Reader interface

`crypto_lab_offline_data.binance_kline_csv.read_binance_kline_csv(path, *, timestamp_unit, ids, clock,
max_rows=DEFAULT_MAX_ROWS, max_bytes=DEFAULT_MAX_BYTES) -> ReadResult`, where `ReadResult` is the slice-1
`Success[tuple[CandleRow, ...]] | Failure` and `CandleRow` is unchanged, so `validate_series`,
`write_normalized_container`, `raw_checksum` and `build_dataset_metadata` consume the rows without change.
`timestamp_unit` is the new `TimestampUnit` (`StrEnum`: `MILLISECONDS = "milliseconds"`,
`MICROSECONDS = "microseconds"`), declared by the caller; the reader never guesses it. The reader reuses
`candle_csv`'s bounded read, decoding, line splitting, number grammar and refusal construction
(package-internal imports, as `cli.py` already does with `normalize.py`); it writes nothing, imports no new
root, and obeys every slice-1 reading (R7: provider faults raise `ProviderContractError`; injected `ids`
and `clock`; no `OSError` or core `ValueError` crosses).

### 2.2 Grammar (strict; every violation is one refusal, nothing is repaired)

- Input path, size ceilings, encoding and line endings: exactly the `ohlcv-csv/1` rules (`INPUT_PATH`,
  `SIZE_CEILING`, `CSV_ENCODING`; UTF-8 without BOM; LF or CRLF; a missing final newline accepted; a blank
  body line refused by the row rule).
- No header row. The documented layout has none and header presence is UNVERIFIED, so the reader accepts
  none: every line is a data row. A first line whose first field is not an unsigned decimal integer is
  `OFFLINE_DATA.CSV_HEADER` at line 1 with the line's length (this is how a documented-column-names header
  line is refused, explicitly, never skipped). An empty file is `OFFLINE_DATA.EMPTY_SERIES` at line 1, the
  line at which the first data row was expected.
- Row shape: exactly twelve comma-separated fields, no quoting, no surrounding whitespace; anything else,
  a blank line included, is `OFFLINE_DATA.CSV_ROW_SHAPE` with the line's length.
- Column mapping (documented order; the field index is one-based):

  | Field | Binance column | Grammar | Mapped to |
  |---|---|---|---|
  | 1 | Open time | unsigned decimal integer `[0-9]+` in the declared unit | `CandleRow.open_time_utc` |
  | 2 | Open | the `ohlcv-csv/1` number grammar, positive | `open` |
  | 3 | High | same, positive | `high` |
  | 4 | Low | same, positive | `low` |
  | 5 | Close | same, positive | `close` |
  | 6 | Volume (base asset) | the number grammar | `volume` |
  | 7 | Close time | unsigned decimal integer in the declared unit | checked, not retained |
  | 8 | Quote asset volume | the number grammar | checked, not retained |
  | 9 | Number of trades | unsigned decimal integer | checked, not retained |
  | 10 | Taker buy base asset volume | the number grammar | checked, not retained |
  | 11 | Taker buy quote asset volume | the number grammar | checked, not retained |
  | 12 | Ignore | any text without a comma; not interpreted (its value is UNVERIFIED) | dropped |

  Fields 2 to 6, 8, 10 and 11 are converted with the slice-1 `_parse_number` rule (exact `Decimal`, the
  canonical-length bound, no sign, no exponent, no whitespace; trailing zeros such as `4.15070000` are
  admitted and canonicalized only at normalization); a violation is `OFFLINE_DATA.CSV_NUMBER` with the
  field's length. Fields 1, 7 and 9 that are not `[0-9]+` are `OFFLINE_DATA.CSV_TIMESTAMP` (1 and 7) or
  `OFFLINE_DATA.CSV_NUMBER` (9) with the field's length.
- Timestamp-unit handling (explicit). With divisor `1_000` for `milliseconds` and `1_000_000` for
  `microseconds`, each of fields 1 and 7 is converted by integer arithmetic (`seconds, remainder =
  divmod(value, divisor)`; `datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds,
  microseconds=remainder * (1_000_000 // divisor))`), never through a float. The admissible window is
  `2017-01-01T00:00:00Z <= t < 2100-01-01T00:00:00Z`; a value outside it is the new refusal
  `OFFLINE_DATA.TIMESTAMP_UNIT` at the row's line with the field's length, which is exactly what a
  millisecond value declared as microseconds (1970) or a microsecond value declared as milliseconds
  (beyond 2100, or beyond `datetime`'s range, which is caught and refused the same way) produces. Derived
  fact: between 2001 and 2286 millisecond values have 13 digits and microsecond values 16. The close time
  must be strictly greater than the open time, else `OFFLINE_DATA.CSV_TIMESTAMP` at the line with the close
  field's length; the documented relation (close = open + interval - 1 unit) is not enforced because the
  reader is timeframe-agnostic; grid, spacing, ordering, gaps and duplicates are the existing
  `validate_series` rules on `open_time_utc`. Whether any real file mixes units is UNVERIFIED; the declared
  unit applies to the whole file.
- Rules apply per row in field order, so a row that breaks two rules is refused by the first; the
  diagnostic names the line and the length only, never the value (section 5.4 of the slice-1 plan).

### 2.3 Refusal set

`RefusalCode` gains one member, `TIMESTAMP_UNIT = "OFFLINE_DATA.TIMESTAMP_UNIT"`, appended after
`METADATA_FIELD` (closed set of fifteen; `diagnostics.py` changes by that one line only). The exact-list pin
`test_the_refusal_codes_are_the_closed_section_five_four_set` in `tests/unit/test_candle_csv.py` gains the one
literal in member order; the README's refusal table gains the row. `line` 0 is never used by this reader
except through the shared `INPUT_PATH` and `SIZE_CEILING` paths.

### 2.4 Command integration

`normalize_command` gains two arguments: `--input-format` with the closed choices `ohlcv-csv/1` (default)
and `binance-spot-kline-csv/1`, and `--timestamp-unit` with the closed choices `milliseconds` and
`microseconds`. `--timestamp-unit` is required with `binance-spot-kline-csv/1` and refused with
`ohlcv-csv/1`; both violations are argparse errors (exit 2, the parser's own text, no value echoed beyond
argparse's own behaviour already documented in the README). The command sequence of the slice-1 plan is
unchanged: read (through the selected reader), validate, `raw_checksum`, draw and snapshot providers,
create `--output` immediately before the first write, write the container, build the metadata, write
`descriptor.json` and `partitions.json`; exits 0, 1, 2, 3 keep their slice-1 meaning, cleanup rules
included. `__main__.py` is unchanged.

### 2.5 Source identity and checksum

`metadata.py` gains `InputFormat` (frozen dataclass `name: str`, `version: str`) with the two constants
`OHLCV_CSV_1 = InputFormat("ohlcv-csv", "1.0.0")` and `BINANCE_SPOT_KLINE_CSV_1 =
InputFormat("binance-spot-kline-csv", "1.0.0")`; `build_dataset_metadata` gains the keyword-only parameter
`source_format: InputFormat = OHLCV_CSV_1`, and `RawSourceProvenance.source_name` and `source_version` come
from it (so every existing call, test and golden is byte-identical). `source_record` stays the bounded input
file name and `source_hash` stays the `raw_checksum` SHA-256 of the input bytes (`raw_checksums` on the
descriptor and `raw_checksum` on the partition unchanged). The `--source` descriptor text keeps its default
`local-fixture`; the fixtures and goldens use `synthetic-binance-fixture`. The published archive `.CHECKSUM`
is outside this slice (section 1).

### 2.6 Limitations recorded on the output

For `binance-spot-kline-csv/1` runs the descriptor's `known_limitations` and the partition's
`quality_observations` carry, beside the P2-B1 literal, the literal
`P2_B2_LIMITATION = "P2-B2: binance-spot-kline-csv/1 fields 7 to 12 (close time, quote asset volume, number of
trades, taker buy volumes, ignore) are validated for shape and not retained; synthetic fixtures only, no real
Binance archive ingested"` (one constant in `metadata.py`, under the core's `BoundedText` bound). The README's
"Interim format and pending obligations" section names both, and the Binance Vision Dataset Terms
(CC BY-NC-SA 4.0, non-commercial; attribution; no redistribution of derivative data feeds) in a short
"Source terms" paragraph stating that this tool reads user-provided extracted files for personal,
non-production research and downloads nothing.

## 3. Fixtures and goldens (all synthetic, labelled)

Directory `offline_data/tests/fixtures/binance/`, every file name prefixed `SYNTHETIC-`; sixty rows per
valid file, `BTCUSDT`, `1m`, eight-decimal values in the documented style, `Ignore` = `0`.

| File | Unit declared | Expectation |
|---|---|---|
| `SYNTHETIC-BTCUSDT-1m-2024-12-31-ms.valid.csv` | milliseconds | sixty consecutive minutes ending 2024-12-31T23:59Z (13-digit times); VALID |
| `SYNTHETIC-BTCUSDT-1m-2025-01-01-us.valid.csv` | microseconds | sixty consecutive minutes from 2025-01-01T00:00Z (16-digit times); VALID |
| `SYNTHETIC-BTCUSDT-1m-gaps-duplicates-us.valid.csv` | microseconds | one missing interval and one exact duplicate; VALID_WITH_WARNINGS through the existing validation |
| `invalid/header-row.csv` | either | documented column names as line 1: `CSV_HEADER` line 1 |
| `invalid/empty.csv` | either | `EMPTY_SERIES` line 1 |
| `invalid/eleven-fields.csv`, `invalid/thirteen-fields.csv` | either | `CSV_ROW_SHAPE` |
| `invalid/ms-declared-us.csv` | microseconds | 13-digit times: `TIMESTAMP_UNIT` line 1, value length 13 |
| `invalid/us-declared-ms.csv` | milliseconds | 16-digit times: `TIMESTAMP_UNIT` line 1, value length 16 |
| `invalid/open-time-before-2017.csv`, `invalid/open-time-at-2100.csv` | as named | window boundaries: `TIMESTAMP_UNIT` (2016-12-31T23:59:59Z refused; 2017-01-01T00:00:00Z accepted in a sibling positive row test; 2100-01-01T00:00:00Z refused) |
| `invalid/close-not-after-open.csv` | microseconds | `CSV_TIMESTAMP` with the close field's length |
| `invalid/open-time-signed.csv`, `invalid/trades-fractional.csv` | microseconds | `CSV_TIMESTAMP` line n; `CSV_NUMBER` line n |
| `invalid/exponent-volume.csv`, `invalid/negative-quote-volume.csv` | microseconds | `CSV_NUMBER` |
| `invalid/zero-price.csv`, `invalid/high-below-low.csv` | microseconds | `CSV_NUMBER` (zero price refused by the reader's grammar as in slice 1); `PRICE_SANITY` from `validate_series` |
| `invalid/unsorted.csv`, `invalid/off-grid-seconds.csv` | microseconds | `ORDERING`; `TIMEFRAME_GRID` from `validate_series` |

Goldens under `offline_data/tests/fixtures/binance/golden/`: `descriptor.json`, `partitions.json` and
`content_hash.txt` for the three valid fixtures, produced by the command and pinned byte-for-byte; two runs
into two fresh directories produce identical bytes and hashes (determinism).

## 4. Tests, guards and documentation

- `tests/unit/test_binance_kline_csv.py`: every row of section 3's table, the exact `Decimal` values and
  tz-aware UTC instants of the valid fixtures (including the 2024-12-31T23:59Z and 2025-01-01T00:00Z unit
  boundaries), the integer-arithmetic conversion (no float; a value with a sub-second remainder yields the
  exact microsecond), per-row rule order, the line and length in each diagnostic and the absence of the
  value, provider draw counts (the `diag_` identifier drawn once per refusal, nothing on success),
  `ProviderContractError` for a refused provider value, and read determinism.
- `tests/unit/test_cli.py`: the two new arguments (defaults, choices, the required-with and refused-with
  couplings as exit 2), a Binance run's descriptor provenance (`source_name`, `source_version`,
  `source_record`, `source_hash`), the P2-B2 literal present for Binance runs and absent for `ohlcv-csv/1`
  runs, golden equality for the three Binance fixtures, cleanup behaviour unchanged.
- `tests/unit/test_metadata.py`: `source_format` default keeps the slice-1 provenance byte-identical; the
  Binance constant is threaded; the limitation literal is within the core bound.
- `tests/unit/test_candle_csv.py`: the closed-set pin gains the one literal.
- `tests/integration/test_core_contract_roundtrip.py`: the three Binance goldens re-parse through the core
  models in strict JSON mode and their content hashes recompute with the core's function.
- `tests/safety/test_boundaries.py`: the module census gains `binance_kline_csv.py`; the import-root
  allowlist and every guard are unchanged; the new module is held to the reader's no-write rule.
- README: a "Binance Spot kline CSV" subsection under "Input format" (identity, column mapping table, unit
  handling, window, header rule, refusals, limitations, terms, SYNTHETIC labelling), the command section's
  two arguments, the refusal table row, the P2-B2 literal, and "Source terms".

## 5. Task decomposition

### Task 1 - The `binance-spot-kline-csv/1` reader and its command integration

**Objective.** Deliver section 2 with section 3's fixtures and goldens and section 4's tests, guards and
documentation, on top of `3a47d4c9`, as one commit.

**Prerequisites.** Branch `project-2-binance-kline-reader` at `3a47d4c9`; the sub-project environment
synced from the unchanged lock (`invoke-offline-uv.ps1 sync`, operator-run if needed); no dependency change.

**Files created.** `offline_data/src/crypto_lab_offline_data/binance_kline_csv.py`,
`offline_data/tests/unit/test_binance_kline_csv.py`,
`offline_data/tests/fixtures/binance/SYNTHETIC-BTCUSDT-1m-2024-12-31-ms.valid.csv`,
`offline_data/tests/fixtures/binance/SYNTHETIC-BTCUSDT-1m-2025-01-01-us.valid.csv`,
`offline_data/tests/fixtures/binance/SYNTHETIC-BTCUSDT-1m-gaps-duplicates-us.valid.csv`,
`offline_data/tests/fixtures/binance/invalid/header-row.csv`,
`offline_data/tests/fixtures/binance/invalid/empty.csv`,
`offline_data/tests/fixtures/binance/invalid/eleven-fields.csv`,
`offline_data/tests/fixtures/binance/invalid/thirteen-fields.csv`,
`offline_data/tests/fixtures/binance/invalid/ms-declared-us.csv`,
`offline_data/tests/fixtures/binance/invalid/us-declared-ms.csv`,
`offline_data/tests/fixtures/binance/invalid/open-time-before-2017.csv`,
`offline_data/tests/fixtures/binance/invalid/open-time-at-2100.csv`,
`offline_data/tests/fixtures/binance/invalid/close-not-after-open.csv`,
`offline_data/tests/fixtures/binance/invalid/open-time-signed.csv`,
`offline_data/tests/fixtures/binance/invalid/trades-fractional.csv`,
`offline_data/tests/fixtures/binance/invalid/exponent-volume.csv`,
`offline_data/tests/fixtures/binance/invalid/negative-quote-volume.csv`,
`offline_data/tests/fixtures/binance/invalid/zero-price.csv`,
`offline_data/tests/fixtures/binance/invalid/high-below-low.csv`,
`offline_data/tests/fixtures/binance/invalid/unsorted.csv`,
`offline_data/tests/fixtures/binance/invalid/off-grid-seconds.csv`,
`offline_data/tests/fixtures/binance/golden/SYNTHETIC-BTCUSDT-1m-2024-12-31-ms.descriptor.json`,
`offline_data/tests/fixtures/binance/golden/SYNTHETIC-BTCUSDT-1m-2024-12-31-ms.partitions.json`,
`offline_data/tests/fixtures/binance/golden/SYNTHETIC-BTCUSDT-1m-2024-12-31-ms.content_hash.txt`,
`offline_data/tests/fixtures/binance/golden/SYNTHETIC-BTCUSDT-1m-2025-01-01-us.descriptor.json`,
`offline_data/tests/fixtures/binance/golden/SYNTHETIC-BTCUSDT-1m-2025-01-01-us.partitions.json`,
`offline_data/tests/fixtures/binance/golden/SYNTHETIC-BTCUSDT-1m-2025-01-01-us.content_hash.txt`,
`offline_data/tests/fixtures/binance/golden/SYNTHETIC-BTCUSDT-1m-gaps-duplicates-us.descriptor.json`,
`offline_data/tests/fixtures/binance/golden/SYNTHETIC-BTCUSDT-1m-gaps-duplicates-us.partitions.json`,
`offline_data/tests/fixtures/binance/golden/SYNTHETIC-BTCUSDT-1m-gaps-duplicates-us.content_hash.txt`.

**Files modified.** `offline_data/src/crypto_lab_offline_data/diagnostics.py` (the one new `RefusalCode`
member `TIMESTAMP_UNIT` only), `offline_data/src/crypto_lab_offline_data/metadata.py` (`InputFormat`, the two
constants, the `source_format` parameter with its slice-1 default, the P2-B2 literal and its threading),
`offline_data/src/crypto_lab_offline_data/cli.py` (the two arguments, reader selection, `source_format`
threading), `offline_data/src/crypto_lab_offline_data/__init__.py` (exports), `offline_data/README.md`,
`offline_data/tests/unit/test_cli.py`, `offline_data/tests/unit/test_metadata.py`,
`offline_data/tests/unit/test_candle_csv.py` (the closed-set pin gains the one literal),
`offline_data/tests/integration/test_core_contract_roundtrip.py`,
`offline_data/tests/safety/test_boundaries.py` (the module census gains `binance_kline_csv.py`; nothing else).

**Not touched.** `candle_csv.py`, `validation.py`, `normalize.py`, `providers.py`, `__main__.py`, the
`ohlcv-csv/1` fixtures and goldens, `offline_data/pyproject.toml`, `offline_data/uv.lock`,
`offline_data/scripts/`, everything outside `offline_data/`.

**Interfaces produced.** `read_binance_kline_csv(path, *, timestamp_unit, ids, clock, max_rows, max_bytes)
-> ReadResult`; `TimestampUnit`; `InputFormat`, `OHLCV_CSV_1`, `BINANCE_SPOT_KLINE_CSV_1`, `P2_B2_LIMITATION`;
`build_dataset_metadata(..., source_format=OHLCV_CSV_1)`; `normalize_command` arguments `--input-format` and
`--timestamp-unit`.

- [ ] **Step 1 Focused RED.** Write section 4's tests first against section 3's fixtures (the goldens are
  added after the first GREEN run captures them; equality tests then pin them).
- [ ] **Step 2** Record the failures through `invoke-offline-uv.ps1 pytest-focused -o addopts=
  tests/unit/test_binance_kline_csv.py tests/unit/test_cli.py tests/unit/test_metadata.py
  tests/unit/test_candle_csv.py tests/integration/test_core_contract_roundtrip.py tests/safety/test_boundaries.py`.
- [ ] **Step 3 Minimum GREEN.** Implement section 2; no change outside the file map.
- [ ] **Step 4 Focused GREEN** (the same focused set), then `ruff-format-all`, `ruff-check-all`, `mypy-all`.
- [ ] **Step 5** Controller gates: `verify-offline.ps1` green (coverage floor unchanged); the core
  `scripts/verify.ps1` green and unchanged in scope; independent review of the full diff (the review reads
  the Binance documentation facts of this plan against the README's column table and unit rule); advisor
  acceptance; commit `feat(offline-data): read binance-spot-kline-csv/1 inputs with explicit timestamp units`.

## 6. Verification, acceptance and completion

Focused tests during implementation; one independent review; the two full verifiers under the host lock,
serial, the core's authoritative verification first when both roots contend; advisor ACCEPT_TASK; controller
commit and publication to `origin/project-2-binance-kline-reader` under the standing authorization of
2026-11-04; never merged into the core's Stage 9 acceptance subject. The slice is complete when Task 1 is
published; the token recorded on acceptance is `P2_BINANCE_KLINE_PLAN_COMPLETE`. The delivery report names
the dispatch, the tested reader and its limits (section 1, 2.6, the UNVERIFIED facts) and the published
commit, and claims no actual market-data ingestion.
