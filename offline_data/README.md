# Crypto Trading Lab - offline historical candle data (`offline_data`)

**Status:** Project 2, first bounded slice - Task 1 authored to plan revision 12, pending
acceptance. The Task 0 scaffold is committed. Task 1 of
`docs/superpowers/plans/2026-11-09-project-2-offline-data-first-slice-implementation-plan.md`
has authored the `ohlcv-csv/1` reader (`candle_csv`), its refusal diagnostics and the
provider contract exception (`diagnostics`) and the injected identity and clock providers
(`providers`), with their tests and fixtures; that work awaits the controller's
verification, independent review and acceptance. Validation and normalization (Task 2)
and metadata emission and the command entry (Task 3) do not exist yet.

## Scope

This sub-project is the first slice of Project 2: read one local historical-candle
fixture in one documented input format, validate and normalize it under the core's
dataset rules, and emit the dataset metadata the core already defines
(`DatasetDescriptor`, `DatasetPartition`) with a deterministic content identity.
Everything is offline: no download, no exchange or broker integration, no credentials,
no live trading, no cloud or server deployment.

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
  registry. Lifting P2-B1 is a separately authorized acquisition and a later task. No
  code in this slice emits a container yet.
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

The one supported input format of this slice is `ohlcv-csv/1`, read by
`crypto_lab_offline_data.candle_csv.read_ohlcv_csv(path, *, ids, clock, max_rows, max_bytes)`.
The reader is strict: every violation below is a refusal, and nothing is truncated,
converted or repaired.

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
  expected; the plan assigns the same code to an empty validated series in Task 2.
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
normalized form (`format_decimal`) belong to Task 2's validation, not to the reader.

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
`read_ohlcv_csv`; the reader draws its providers only when it builds a refusal, so a
faulty provider is never observed on an accepted input. It is the only exception that
crosses the sub-project's public boundary: neither the core `ValidationError` nor an
`OSError` escapes.

## Safety scope

Unchanged from the core: personal, local-only, research only; no real-money orders, no
credentials or API keys, no leverage, futures, margin or shorting, no implicit network
access, no Docker, cloud or server deployment.
