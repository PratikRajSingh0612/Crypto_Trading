# Project 3 VectorBT first engine slice implementation plan

Revision: 1
Task: P3-T1
Status: Proposed for independent plan review; not a dispatch instruction.

## Authority and subject

Apply the owner authorization and parallel-priority instruction recorded on 2026-11-15. Reuse sections (a)–(d) and the consistency review of `Project3_Prep/vectorbt-readiness-brief-2026-11-10.md`, narrowed here to an in-memory engine slice.

The implementation subject is:

- Worktree: the registered Project 3 worktree `Crypto_Trading-worktrees/project-3-vectorbt-adapter` (a sibling of the main checkout).
- Branch: `project-3-vectorbt-adapter`.
- Published bootstrap base: `1abd49e5b67fe4856ec5d974d90414c5dbfe901c`.
- Environment: this worktree’s `vectorbt_adapter/.venv`, using the approved uv-managed CPython 3.12.
- Immutable `vectorbt_adapter/uv.lock` SHA-256: `7afac95bff041b2b42beaa30b76cd9bfdc3823af872f99fce5e2e36e1c187210`.
- Locked runtime: VectorBT Community `1.2.0`, NumPy `2.5.4`, pandas `3.1.1`, Numba `0.68.1`, llvmlite `0.50.0`. The older NumPy/pandas versions in the readiness brief do not apply.
- Licence provenance: the bootstrap result records Apache 2.0 with Commons Clause, with installed licence SHA-256 `a914859a115b70e80956a3cbd613139ad74c04e5d1bd38da8bcc16725822ec84`. Retain the internal-research limitation in the README.

The owner records supersede the earlier acquisition blocker for this isolated workstream. They do not authorize another acquisition or a dependency change.

Canonical references are the reviewed `src/crypto_lab/strategy/evaluation.py`, `tests/fixtures/strategy/sma_cross_long.valid.yaml`, the associated golden outputs, and `_sma_cross_long_closes` in `tests/unit/strategy/test_strategy_evaluation.py`. Read these as sources; do not import the core into the adapter environment.

GitNexus remains `DISABLED_WITH_EVIDENCE`; use source, reference and diff inspection.

Planning observations: local HEAD and the local remote-tracking ref matched the bootstrap base, and the lock hash matched. Interpreter discovery encountered a sandbox denial opening the uv cache; Git also reported inaccessible user ignore configuration. No engine execution, test, quality check or full gate was run by this advisor. Bootstrap identity evidence is not a fresh execution result.

## P3-T1 — Execute and independently check one in-memory engine slice

### Scope and implementation boundary

Implement a small callable that computes the fixed strategy’s signals, invokes the genuine installed `Portfolio.from_signals`, and exposes its native portfolio records plus Decimal inspection values.

Keep the project virtual: retain `package = false`, existing project metadata, dependency declarations and lock bytes. Import adapter source during pytest through the sub-project’s explicit `pythonpath = ["src"]`.

The complete worker source manifest is:

| Action | Exact path |
|---|---|
| Modify | `vectorbt_adapter/pyproject.toml` |
| Create | `vectorbt_adapter/README.md` |
| Create | `vectorbt_adapter/scripts/verify-vectorbt.ps1` |
| Create | `vectorbt_adapter/src/crypto_lab_vectorbt_adapter/__init__.py` |
| Create | `vectorbt_adapter/src/crypto_lab_vectorbt_adapter/signals.py` |
| Create | `vectorbt_adapter/src/crypto_lab_vectorbt_adapter/simulation.py` |
| Create | `vectorbt_adapter/src/crypto_lab_vectorbt_adapter/conversion.py` |
| Create | `vectorbt_adapter/tests/conftest.py` |
| Create | `vectorbt_adapter/tests/unit/test_signals.py` |
| Create | `vectorbt_adapter/tests/unit/test_conversion.py` |
| Create | `vectorbt_adapter/tests/integration/test_engine_slice.py` |
| Create | `vectorbt_adapter/tests/safety/test_boundaries.py` |

Use these exact file bounds, with no directory or wildcard write grant. No worker modification outside `vectorbt_adapter/` is authorized. The controller-owned reviewed plan is outside this implementation manifest.

Do not modify either launcher, AGENTS.md, core source/tests, shared schemas, migrations, root metadata/lock, Project 2 files, or controller code. Ordinary ignored test/tool caches and engine JIT caches are incidental execution state, never deliverables.

### 1. Freeze the strategy and synthetic input

Support the canonical `sma_cross_long` rule with:

- Fast SMA: trailing 20 closes; feature missing at indices below 20.
- Slow SMA: trailing 50 closes; feature missing at indices below 50.
- Entry at `t`: all four current/prior feature values present, fast[t] > slow[t], and fast[t−1] ≤ slow[t−1].
- Exit: the inverse inequalities.
- Missing operands produce false signals.
- Fraction of available quote: exactly 1.
- Spot, one asset, long only, initially flat.

Compute rolling means in adapter code using explicit trailing windows and minimum periods, then apply the canonical warm-up masks. Compute crossover booleans directly; do not use VectorBT’s crossover helper. Reject overlapping entry/exit signals before simulation.

Build the sole execution dataset in test code:

- 54 hourly bars.
- Close[t] = 1000 + t for indices 0–50, followed by 500, 1050, 1500.
- Open = high = low = close; volume = 1.
- Explicit UTC `DatetimeIndex`, starting `2026-01-01T00:00:00Z`, frequency `1h`.
- Index labels denote bar opening times.

No candle file, dataset normalization command, network source or serialized object supplies this input. Unit tests may use small feature-value arrays to check equality and missing-value predicates; these are not additional engine datasets.

The frozen signal oracle is exit only at index 51 and entry only at index 53. Pin these feature values:

| Index | Fast SMA | Slow SMA |
|---|---:|---:|
| 50 | 1040.5 | 1025.5 |
| 51 | 1013.95 | 1015.48 |
| 52 | 1014.85 | 1016.44 |
| 53 | 1038.2 | 1026.38 |

Validate finite positive prices and an aligned, unique, increasing UTC hourly index. The callable accepts only the two named timing modes and the tested fee rates, 0 and 0.001. It is not a general strategy/configuration interpreter.

### 2. Make execution semantics explicit

SAME_BAR_CLOSE executes an unshifted signal at that row’s supplied close price. Its economic fill timestamp is bar opening time plus one hour.

NEXT_BAR_OPEN shifts both signal arrays forward exactly one row, fills the introduced first row with false, and executes at the destination row’s supplied open price. Discard a signal whose destination lies beyond the dataset. Its fill timestamp is the destination bar’s opening time.

Pass actual finite price arrays, avoiding any engine fallback for an unavailable open. Preserve the distinction between VectorBT’s row label and the economic fill timestamp.

Use the following explicit `Portfolio.from_signals` arguments. Grouped names below each denote separate supplied arguments.

| Argument | Explicit value | Reason |
|---|---|---|
| `close` | Aligned float64 close Series | Mark-to-market prices |
| `entries`, `exits` | Adapter-computed boolean arrays, shifted only for NEXT_BAR_OPEN | Canonical signal and timing rules |
| `short_entries`, `short_exits` | `None`, `None` | Select the documented direction-based entries/exits interface |
| `signal_func_nb`, `signal_args` | Installed `nb.no_signal_func_nb`, `()` | Select VectorBT’s built-in interpretation of supplied arrays; no custom callback |
| `direction` | `"longonly"` | Prohibit short positions |
| `price` | Close Series for SAME_BAR_CLOSE; open Series for NEXT_BAR_OPEN | Explicit execution price |
| `open`, `high`, `low` | Supplied float64 OHLC Series | No inferred OHLC values |
| `init_cash` | `15000.0` | Fixed starting quote balance |
| `size`, `size_type` | `1.0`, `"percent"` | Spend the complete available quote budget, including fees |
| `fees` | `0.0` in A/B; `0.001` in C | Explicit taker fee rate |
| `fixed_fees`, `slippage` | `0.0`, `0.0` | No fixed charge or slippage; maker fees unused |
| `min_size` | `1e-8` | Explicit minimum quantity, below every expected fill |
| `max_size` | `np.inf` | No additional size cap |
| `size_granularity` | `np.nan` | Disable engine quantity flooring |
| `allow_partial` | `True` | Permit native cash-budget sizing; no canonical FULL_FILL claim |
| `accumulate` | `False` | Repeated entries do not add to an existing long; exits close it |
| `lock_cash`, `cash_sharing` | `False`, `False` | One independent long-only cash account |
| `upon_long_conflict` | `"exit"` | Defensive setting; adapter rejects overlapping signals first |
| `upon_short_conflict`, `upon_dir_conflict`, `upon_opposite_entry` | `"ignore"` each | Disable unused short/opposite-direction paths |
| `reject_prob`, `raise_reject`, `log` | `0.0`, `True`, `False` | No random rejection; surface rejected orders; no simulation log records |
| `val_price` | The selected execution-price Series | Explicit valuation input |
| `ffill_val_price`, `update_value` | `False`, `False` | No missing-price filling or intra-row value update |
| `use_stops`, `sl_stop`, `sl_trail`, `tp_stop` | `False`, `np.nan`, `False`, `np.nan` | Disable stops |
| `stop_entry_price`, `stop_exit_price` | `"close"`, `"stoplimit"` | Pin inactive stop settings |
| `upon_stop_exit`, `upon_stop_update` | `"close"`, `"override"` | Pin inactive stop policies |
| `adjust_sl_func_nb`, `adjust_sl_args` | Installed `nb.no_adjust_sl_func_nb`, `()` | No stop adjustment |
| `adjust_tp_func_nb`, `adjust_tp_args` | Installed `nb.no_adjust_tp_func_nb`, `()` | No profit-stop adjustment |
| `group_by`, `call_seq` | `False`, `"default"` | Single ungrouped asset, deterministic call order |
| `freq` | `"1h"` | Explicit bar frequency |
| `seed` | `0` | Pin seed despite disabled stochastic rejection |
| `max_orders`, `max_logs` | Number of bars, `1` | Explicit record capacity; logging disabled |
| `init_temp_records`, `attach_call_seq` | `False`, `False` | Explicit temporary-record and retained-call-sequence policy |
| `broadcast_named_args`, `broadcast_kwargs`, `template_mapping`, `wrapper_kwargs` | Empty dictionaries each | No custom broadcasting/template/wrapper configuration |
| `engine` | `"numba"` | Explicit execution backend; no automatic Rust selection |
| `fillna_close` through constructor kwargs | `False` | No close-price filling |
| `trades_type` through constructor kwargs | `"exittrades"` | Explicit trade representation, including open trades |

All Series share the identical single-asset index. Pass no additional arbitrary kwargs.

VectorBT percent sizing treats fraction `f` as a budget of `f × available cash` inclusive of fees. With zero fixed fees/slippage, bought quantity is budget / (price × (1 + fee rate)). This convention agrees with the zero-fee examples; the fee-bearing result is a declared native convention, not an equivalence ruling on canonical sizing.

The conflict setting does not establish general EXITS_BEFORE_ENTRIES support. This slice rejects the conflicting case.

### 3. Define the numerical boundary

Use float64 for engine prices, fees, indicators, quantities and native accounting. Keep the independent oracle in Decimal, under a local context of precision 34 and ROUND_HALF_EVEN.

Provide one outbound conversion helper in `conversion.py`: reject non-finite native financial values, then convert using `Decimal(repr(float(value)))`. Use it consistently for inspection values. Preserve native records separately.

This conversion describes a float result; it does not restore Decimal execution accuracy. Do not quantize engine orders, feed rounded inspection values back into accounting, or describe inspection values as canonical normalized results.

Comparisons must use:

- Exact equality for signal masks, counts, IDs, sides, indices, statuses and timestamps.
- Exact equality for the integer/half-integer feature values that are exactly representable, and all Case A/B financial results.
- Absolute tolerance `1e-10`, relative tolerance zero, for non-binary-exact SMA values. This allows float64 rolling arithmetic error while remaining far below the frozen crossover separations.
- Case C quantity tolerance `1e-12`; quote amounts and derived trade accounting tolerance `1e-9`; relative tolerance zero. The divisions and fee subtraction introduce binary rounding, at values around 10 and 15000. These limits are conservative relative to their float64 spacing.
- Exact order execution price 1500 and zero cash/zero exit fees where specified below.

Do not widen tolerances to obtain a pass. A breach requires investigation and renewed review of any proposed policy change.

### 4. Check Cases A/B/C without an engine-derived oracle

Compute expected features/signals and accounting independently in test code. Do not call VectorBT, pandas rolling operations or adapter calculation helpers to derive expected results.

Compare expectations against native orders, exit-trade and position records, and the complete cash, asset-quantity and equity series.

| Case | Independent expected result |
|---|---|
| A: SAME_BAR_CLOSE, fee 0 | Exit at 51 while flat produces no order. One BUY: id 0, column 0, index 53, quantity 10, price 1500, fees 0. Cash is 15000 through index 52 and 0 at 53. Position is 0 through 52 and 10 at 53. Equity is 15000 at every bar. |
| B: NEXT_BAR_OPEN, fee 0 | Exit shifts to 52 while flat. Entry shifts beyond the final row. Zero orders, trades and positions; cash/equity remain 15000 and asset quantity remains 0. |
| C: SAME_BAR_CLOSE, fee 0.001 | One BUY at 53 and price 1500. Quantity = 10000/1001; fee = 15000/1001; final cash = 0; final equity = 15000000/1001. Before 53, cash/equity are 15000 and quantity is 0. |

For A/C, require exactly one long OPEN trade and one open position, with entry index 53, mark index 53, mark price 1500 and exit fees 0. PnL is 0 in A and minus the entry fee in C.

VectorBT’s open-trade `exit_idx`/`exit_price` represent the final mark. They must not become a fabricated SELL, closed trade or liquidation fill.

Retain all three cases: A establishes exact accounting, B establishes the end-of-input timing boundary, and C establishes fee-inclusive sizing and numerical treatment.

Add focused unit checks for the one-row signal shift, first-row false insertion, trailing-signal loss, execution-price selection, warm-up boundaries, inclusive prior-bar crossover equality and missing operands. These supplement Case B, which contains no positive next-open fill. Positive NEXT_BAR_OPEN fills and closed round trips remain unaccepted by this slice.

### 5. Prove genuine execution and guard network access

In a test, before running the cases, assert:

- Python is 3.12.
- Resolved interpreter and `sys.prefix` belong to this checkout’s `vectorbt_adapter/.venv`.
- Distribution version and imported `vectorbt.__version__` are both `1.2.0`.
- The resolved imported `vectorbt/__init__.py` and distribution location belong to that environment’s `Lib/site-packages`, excluding checkout substitutes and other worktrees.
- Installed NumPy/pandas versions match `2.5.4`/`3.1.1`.
- The returned object is the actual installed `vectorbt.Portfolio`, with engine preference `"numba"` and native structured records.

No test may stub, mock, replace or fabricate an engine, Portfolio, engine records or engine execution function. Missing identity or execution capability fails the test; it is never skipped or replaced.

Install a test-process network denial guard in `pytest_sessionstart`, before collection and any engine import. Deny socket connection, DNS-resolution, bind and datagram-send audit events, recording event names only. Require zero attempts during identity and execution tests, including attempts whose exceptions a dependency catches. Include a guard self-test that explicitly expects denial before any network operation proceeds.

Keep engine import lazy until execution; package imports must not launch simulation, inspect the environment or access files/network. Add focused source-boundary checks against adapter environment access, network clients, subprocess launch and serialization/deserialization APIs.

Load no pickle/dill or serialized Portfolio input and invoke no serialization API. The transitive presence of requests/dill is not permission to use them. The network test guards the exercised Python paths; it does not establish an operating-system sandbox.

### 6. Add local tool configuration and the sub-project gate

Modify only tool configuration in `vectorbt_adapter/pyproject.toml`:

- Ruff: Python 3.12, line length 88, source roots `src`/`tests`, LF formatting; lint selections `B`, `DTZ`, `E`, `F`, `I`, `PT`, `RUF`, `S`, `UP`; test-only `S101` exemption; pytest fixture-parentheses setting matching the accepted sub-project pattern.
- Mypy: Python 3.12, `strict = true`, `files = ["src", "tests"]`. Permit missing third-party typing only for `vectorbt`/`vectorbt.*` and `pandas`/`pandas.*`. Keep owned interfaces typed and any untyped engine access confined to the engine boundary.
- Pytest: `testpaths = ["tests"]`, `pythonpath = ["src"]`, strict configuration and markers, strict xfail behavior, branch coverage for `crypto_lab_vectorbt_adapter`, terminal missing-line reporting and coverage floor 90%.
- Coverage: branch measurement and source limited to the adapter package; report floor 90%, precision 2, missing lines shown.

Do not install typing packages, add dependencies, change package metadata or regenerate the lock.

Define command prefix P, executed from the worktree root, as:

`C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./vectorbt_adapter/scripts/invoke-vectorbt-uv.ps1`

Focused RED/GREEN commands:

- `P pytest-focused -o addopts= tests/unit/test_signals.py tests/unit/test_conversion.py -q`
- `P pytest-focused -o addopts= tests/integration/test_engine_slice.py -q`
- `P pytest-focused -o addopts= tests/safety/test_boundaries.py -q`

Record a meaningful failing assertion for each production behavior before its minimum implementation, then the corresponding passing result. A missing module or broken tool invocation alone is insufficient RED evidence.

The five quality checks are:

1. `P ruff-format-all`
2. `P ruff-check-all`
3. `P mypy-all`
4. Worker: `P pytest-focused tests/unit tests/integration tests/safety -q`, retaining configured strictness and coverage.
5. Controller: `git diff --check -- vectorbt_adapter`

The format profile checks formatting; it does not format files. Correct formatting through the bounded edits.

Create `vectorbt_adapter/scripts/verify-vectorbt.ps1`, following the accepted `verify-offline.ps1` structure. Its complete behavior is:

1. Accept no caller-selected operations; enable StrictMode and terminating PowerShell errors.
2. Resolve the sub-project root from the script location and its fixed sibling launcher path.
3. Assert the lock SHA-256 specified above.
4. Push the sub-project working directory.
5. Invoke a fresh PowerShell child for each fixed launcher profile, in order: `lock-check`, `sync`, `ruff-format-all`, `ruff-check-all`, `mypy-all`, `pytest-all`.
6. Check the native exit code immediately after every child. Stop at the first failure, retain its nonzero code and print the failing stage.
7. Run `git diff --check -- .` from the sub-project root and check its exit code.
8. Reassert the immutable lock hash on the successful route.
9. Restore the caller’s working directory in `finally`; exit zero only if every stage succeeded. A PowerShell exception without a captured native failure exits 1.

The script accepts no alternate launcher, test target, profile or network option. It does not invoke the core verifier itself.

The controller alone runs this gate. The worker remains restricted to the four existing worker profiles; `pytest-all`, lock/sync and acquisition profiles are not worker permissions.

### 7. Document the result and preserve the acceptance boundary

The README must state:

- The exact environment/lock/engine identities and licence provenance.
- The fixed strategy, dataset, timing, price, sizing, fees, float64 conversion and tolerance policies.
- Cases A/B/C and independently reproducible arithmetic.
- How to run focused checks and the controller gate.
- That results are an isolated engine slice with native records and inspection values, not finalized canonical artifacts.

Carry these limitations explicitly:

- Float64 indicators/accounting and fee-inclusive percent sizing are declared modeling limitations, not general canonical equivalence.
- No instrument precision/order-intent quantization, general conflict priority, partial-fill equivalence, positive next-open fill acceptance or closed-trade acceptance.
- No parameter sweep, optimization, external dataset, market-data fetch, exchange integration, credentials or live operation.
- No executable `describe`/`validate`/`run` protocol, supervisor/heartbeat integration, catalog identity or installed adapter distribution.
- EngineRunRequest still carries hashes without the strategy document, resolved parameters and candle partition delivery needed for an executable adapter. This slice introduces no private delivery convention.
- Candidate/native artifact export, provenance-linked normalized results, manifests, finalization and Parquet remain later work. No new Parquet dependency is authorized.
- An isolated test pass establishes neither integrated backtesting nor Project 3 completion.

### 8. Verify, review, accept and publish the exact subject

Before worker dispatch, require independent plan APPROVE, advisor plan acceptance, exact committed plan/base identity, registered bounds/publication route and clearance of the prerequisites listed after this plan.

The operator must re-confirm the managed interpreter with `uv python find --managed-python --system --no-python-downloads 3.12` and check the existing frozen environment through the offline launcher route. A missing interpreter/package stops execution; do not acquire or substitute anything.

Keep Project 1 first, at most two product workers, and heavy verification serial under the existing shared host lock. Treat the first engine/JIT test workload as heavy. Do not run engine tests during another verifier’s exclusive window.

After focused RED/GREEN and quality checks, the controller requests full verification with empty targeted-test overrides. Its registered ordered gate is:

1. `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./vectorbt_adapter/scripts/verify-vectorbt.ps1`
2. `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/verify.ps1`

The unchanged core verifier is mandatory on every full attempt. Budget approximately 45 minutes for it, plus adapter import/JIT/test time. Preserve every core schema, migration, test, coverage, build and distribution gate. Report every warning, skip, failure and stage left unrun. A core guard failure does not authorize widening this task’s bounds.

Bind evidence to the exact parent, complete implementation-path inventory and content digest, unchanged launcher/lock identities, environment identities and verifier contents. Neither bootstrap evidence nor an earlier core pass covers this subject.

Then:

1. Obtain independent implementation review APPROVE on the exact fully verified subject, with the worker idle. Review actual engine execution, independent arithmetic, numerical limits, network guard, full diff and scope.
2. Reverify and rereview any changed subject.
3. Record advisor task acceptance against PASSED full verification and APPROVE review.
4. Stage only the accepted implementation manifest; verify the staged path inventory. Commit with a message such as `feat(vectorbt-adapter): prove isolated SMA engine slice`.
5. Scan added lines in all outgoing commits, including the separately owned plan commit.
6. Publish non-force only through `refs/heads/project-3-vectorbt-adapter:refs/heads/project-3-vectorbt-adapter` to `origin`.
7. Confirm the remote commit and record verification, review, acceptance and publication identities.

Do not merge or publish to main or a Project 2 branch. Completion means only P3-T1 accepted and published.

Estimated additional Project 2 root turns through publication: 18–28, including plan review/acceptance, mission setup, worker checkpoints, one bounded correction cycle, full verification, independent implementation review and publication. From 117/200 used, this projects approximately 135–145/200. Waiting time and unexpected failures may extend elapsed time; the turn budget cannot waive acceptance gates.
