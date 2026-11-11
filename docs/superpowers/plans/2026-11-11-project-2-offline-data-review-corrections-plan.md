# Project 2: offline-data review corrections — bounded implementation plan

**Status.** Revision 1, proposed under STANDING OWNER AUTHORIZATION 2026-11-10, AUTONOMOUS PROGRAMME DELIVERY (extracted verbatim from the advisor's selection of 2026-11-11 01:15Z; the controller session substituted the registered PowerShell executable form in the six command lines, as in the slice-3 plan, and nothing else). Awaiting independent plan APPROVE and advisor DELEGATED_PLAN_ACCEPTED. This document is not an acceptance record.

**Plan location.** `docs/superpowers/plans/2026-11-11-project-2-offline-data-review-corrections-plan.md`.

**Branch and base.** New branch and worktree `project-2-offline-data-review-corrections`, descending from published SQLite consumer-test commit `970c1fb57005036e4e162190edeecdebf7935ceb`, which descends from reader commit `4d70f673a004b47883388fa45a0d93c8daa9167a`. The controller commits this reviewed plan separately; that plan commit becomes the implementation gate’s base_commit. Historical task identities remain closed.

**Readiness.** NOT_READY until exact plan acceptance, policy registration, both offline environments, execution binding and resource availability are recorded. No Stage 9 merge is required for this isolated correction.

## 1. Authority, evidence and consumed versions

Unprefixed source paths refer to the product tree at `970c1fb5`; line references identify that inspected version. CTL means `Crypto_Lab_Dev_Controller-dev`; P2CTL means `Crypto_Lab_Dev_Controller_P2`.

- `P2CTL/config/mission_checkpoint.md:185-258`: standing programme authority, priorities, readiness, ownership, resource limits and publication.
- `P2CTL/evidence/mission/reviewer/P2B-T1-review-d1c36d6e/reviewer.stdout.log:1`: the field-12 carriage-return MINOR.
- `P2CTL/evidence/mission/reviewer/P2-T3-review-442d0800/reviewer.stdout.log:1`: README exit-2 wording and entry-point scanner MINORs.
- `docs/superpowers/plans/2026-11-10-project-2-binance-kline-reader-plan.md:79-122`: existing grammar and governing field-12 clause.
- `offline_data/src/crypto_lab_offline_data/candle_csv.py:69-72`: LF/CRLF splitting leaves an unmatched carriage return in the logical row.
- `offline_data/src/crypto_lab_offline_data/binance_kline_csv.py:173-250`: header precedence, row parsing and unchecked field 12.
- `offline_data/tests/unit/test_binance_kline_csv.py:1375-1422`: opaque-text controls and existing trailing-CR acceptance.
- `offline_data/tests/safety/test_boundaries.py:748-797`: entry-point call-shape scanner; `:1643-1710`: its controls.
- `offline_data/README.md:643-672` and `:745-748`: argument-output wording.
- `offline_data/pyproject.toml:52-53` and `:76-99`: existing core dependency, strict typing and coverage floor.
- `offline_data/scripts/invoke-offline-uv.ps1:21-33`, `:168-198`, `:221-328`: committed offline profiles.
- `offline_data/scripts/verify-offline.ps1:21-49`: sub-project full gate.
- `docs/superpowers/plans/2026-11-11-project-2-sqlite-dataset-registration-contract-plan.md:158-227`: task-file syntax and full acceptance route.

Consumed contracts remain fixed:

- Core source: accepted `079395bec70f1deda406d0ca14b2d4bf79aaf063`, preserved in this branch’s core files.
- Dataset descriptor and partition schema versions: `1.0.0`.
- Metadata hash profile: `dataset-metadata/v1`.
- Formats: `ohlcv-csv/1`, `binance-spot-kline-csv/1`.
- Provenance source versions: existing `1.0.0` values.
- Output: `normalized-ndjson/0.1.0`, column schema `0.1.0`.
- Distribution: existing `crypto-lab-offline-data` version `0.1.0`.
- Existing locks, dependency pins, launchers and verification floors are unchanged.

If main advances during this task, retain this consumed core version. Do not import Stage 9 changes into this branch; later combined integration needs its own reviewed route.

## 2. Scope and narrow contract amendment

Deliver the three outstanding review corrections as one implementation task, with focused regressions and related README reconciliation.

This plan is a bounded amendment to the reader plan’s section 2.2. It supersedes only the conflicting field-12/line-ending wording for this task; it does not reopen the completed reader mission or replace its unrelated requirements.

**Model decision under standing owner delegation; not a human message or approval.**

Class: plan_wording.

Summary: Resolve the Binance reader’s permissive field-12 wording against its strict line-ending rule.

Affected clauses: Reader plan section 2.2, lines 81-98 and 114; corresponding reader documentation and trailing-carriage-return acceptance test.

Chosen solution: Reject residual carriage returns in field 12 after fields 1-11 pass. Return existing OFFLINE_DATA.CSV_ROW_SHAPE with the logical row number and complete logical-row length. Preserve the existing splitter; never strip or repair input.

Preserved guarantees: Existing valid fixtures, goldens, identities, timestamps, hashes and output bytes; earlier-rule precedence; redacted diagnostics; provider behavior; import purity; read-only parsing; unchanged full acceptance gates.

Attach this ruling through delegated_decision on the first IMPLEMENT for P2C-T1 so the controller records OWNER_DELEGATED_DECISION before execution.

### Field-12 behavior

1. Keep the existing LF/CRLF splitter and acceptance of a missing final newline.
2. Preserve the existing first-line header check, row ceiling, twelve-field count and checks of fields 1-11 in their present order.
3. After those checks, refuse any residual carriage return in field 12 with OFFLINE_DATA.CSV_ROW_SHAPE. Its value_length is len(record), including residual carriage returns but excluding the consumed LF/CRLF delimiter.
4. This covers a lone terminal CR, CR CR LF endings and CR embedded in the opaque field.
5. Field 12 otherwise remains uninterpreted and dropped. Existing acceptance of empty text, spaces, quotation marks and exponent-looking text remains. Commas remain delimiters; no CSV quoting or escaping is introduced.
6. Earlier failures retain precedence. An invalid price plus a field-12 CR remains CSV_NUMBER; a malformed first field on line 1 remains CSV_HEADER.
7. Introduce no refusal code, public parameter, new format identity or source-version change.

### Entry-point guard

Tighten the existing AST scanner to require the guarded call’s complete argument shape:

- One positional argument: literal None.
- Exactly ids and clock keyword arguments; either keyword order is equivalent.
- ids is the bare zero-argument Uuid4IdProvider() call.
- clock is the bare zero-argument SystemClock() call.
- No extra positional arguments, duplicate or extra keywords, starred arguments, keyword unpacking, alternate constructors or constructor arguments.
- Preserve the existing exact main guard, single outer raise SystemExit(...), absence of a raise cause and existing surrounding import-time restrictions.

The production entry point already satisfies this shape and is not modified. Keep other guard policies intact.

### README correction

Correct argument-parsing documentation to match existing behavior:

- Application Failure/provider messages use standard output and exclude submitted values and paths.
- Argparse exit-2 usage/errors use standard error and may echo caller argv for unrecognized arguments.
- Preserve the narrower no-value-echo guarantees of the existing custom converters and coupling errors.
- Help uses argparse’s existing standard-output behavior.
- Describe field 12 and residual-CR refusal consistently with this amendment.

Also reconcile only these already-established status facts: the reader was published at 4d70f673, and the temporary SQLite consumer test was published at 970c1fb5. The stale text is the second-slice status and pending-registration prose; the slice-1 Task 3 table row already says committed. Do not claim acceptance of this correction before controller evidence exists.

### Exclusions

No core, shared schema, migration, lock, dependency definition, launcher, verifier, conftest, production CLI or production entry-point change. No committed fixture or golden changes, new production modules, guard exemptions or lowered thresholds.

No network/source access, real-data download, dependency acquisition, engine installation/import/execution, persistent registration, production registration command, artifact-finalizer integration or P2-B1/P2-B2/P2-B3 lift. Existing temporary-database tests remain in the acceptance suite.

No Stage 9/main merge or new publication destination. Controller publication uses only the existing authorized remote and the registered branch.

## 3. Required tests

Use synthetic test values written under tmp_path; do not acquire data or add fixture files.

**Reader regressions.**

- Test both declared timestamp units.
- Refuse lone terminal CR, CR CR LF rows and embedded field-12 CR.
- Exercise failures on line 1 and a later body line, including a malformed ending before the final line.
- Retain the CR-only multi-row refusal.
- Pin one structured diagnostic: existing error code, logical line, complete logical-row length, standard redacted message and no input-value/path disclosure.
- Prove one diagnostic-ID and clock draw on the new refusal, no dataset/partition-ID draws, and unchanged provider-fault propagation.
- Preserve positive LF, CRLF and missing-final-newline cases and all existing opaque-text controls.
- Add competing-failure controls proving header, row-width and earlier numeric/time rules retain precedence.

**Guard regressions.**

Add synthetic AST negative controls for omitted argv/providers, non-None argv, wrong provider names, swapped provider values, constructor arguments, extra or duplicate keywords, extra positional arguments and unpacking. Previously admitted incomplete calls become negative controls. Retain existing negative controls and positive controls for the production shape, permitted surrounding pure code and equivalent keyword ordering. Never execute the synthetic payloads.

**Command regressions.**

- Feed malformed-CR Binance input through normalize_command using injected providers. Require exit 1, the canonical CSV_ROW_SHAPE Failure, and no output-directory creation or output-file writes.
- Pin the existing exit-2 behavior with a harmless unrecognized-argument sentinel: standard-error usage/error output may contain that argv token; standard output is empty; no provider draws or output writes occur.
- Retain existing custom-converter/coupling no-echo tests and module-entry-point behavior tests.

**Preserved consumers.**

Run the existing OHLCV reader, core metadata round-trip and temporary SQLite registration modules. Existing committed goldens remain byte-identical; the full gate retains the metadata and normalization suites.

## 4. Task decomposition

### Task 1 - Close the offline-data reader, entry-point guard and README review findings

**Objective.** Implement sections 2 and 3 as one coherent correction over the preserved P2 deliveries.

**Prerequisites.** Independent plan APPROVE and advisor DELEGATED_PLAN_ACCEPTED bound to the exact plan bytes and commit; gate based on that plan commit; registered worktree, branch and publication refspec; unique mission identity; both environments synchronized offline; admitted launcher profiles and resource preflight passed.

**Files created.** None.

**Files modified.** `offline_data/src/crypto_lab_offline_data/binance_kline_csv.py`,
`offline_data/tests/unit/test_binance_kline_csv.py`,
`offline_data/tests/unit/test_cli.py`,
`offline_data/tests/safety/test_boundaries.py`,
`offline_data/README.md`.

**Writable boundary.** These five exact files are the complete implementation map. The plan itself is committed separately by the controller before dispatch and is not worker-writable. Do not use directory bounds or path patterns.

**Execution.** Run from the registered worktree root. The commands name the registered PowerShell executable exactly as the committed launcher profiles and the dispatch prompt do (a fixed system path, not a machine-local user path).

First add the reader and scanner regressions and record focused RED:

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/invoke-offline-uv.ps1 pytest-focused -o addopts= tests/unit/test_binance_kline_csv.py tests/safety/test_boundaries.py -q
```

Implement the minimum correction, then run the same focused set to GREEN. Add the command regressions and README changes, then run:

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/invoke-offline-uv.ps1 pytest-focused -o addopts= tests/unit/test_binance_kline_csv.py tests/unit/test_cli.py tests/unit/test_candle_csv.py tests/safety/test_boundaries.py tests/integration/test_core_contract_roundtrip.py tests/integration/test_sqlite_dataset_registration.py -q
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/invoke-offline-uv.ps1 ruff-format-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/invoke-offline-uv.ps1 ruff-check-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/invoke-offline-uv.ps1 mypy-all
```

The formatting profile checks only; hand-edit authorized files to fix formatting. No direct uv, Python, pytest or product-command invocation. Lock checks and synchronization are operator/controller prerequisites.

- [ ] Record meaningful RED for the newly required reader refusal and scanner restrictions.
- [ ] Implement the minimal reader and scanner changes; retain existing positive behavior.
- [ ] Complete command regressions and the bounded README corrections.
- [ ] Pass the focused regression set and three quality profiles.
- [ ] Leave the worker idle with exactly the five authorized changed files.
- [ ] Complete section 5 through the controller; the worker does not verify, stage, commit or publish.

**Commit message.** `fix(offline-data): reject residual carriage returns and tighten entry-point guards`

## 5. Verification, review, publication and completion

The controller must issue VERIFY with verification_scope=full and verification_targets=[].

Run these unchanged scripts, in this order, from this worktree:

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/verify-offline.ps1
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/verify.ps1
```

Both must be PASSED for the same final subject and recorded execution environment. Preserve the P2 branch-coverage floor of 98.61 percent and every configured core schema, migration, coverage, build, distribution and hygiene check. Report all warnings, skips and failures. Earlier slice passes and Workstream A’s verification do not cover this correction.

At most two product implementation workers may exist. All heavy verification is serial under .crypto-lab-host/verifier.lock. Workstream A has priority through S9-T9 acceptance and Stage 9 integration, including the merged-main verifier, hygiene checks and publication.

Do not start any B controller VERIFY during that reserved window, including an apparent gap between A’s runs. Keep dispatch_wait_markers=[verify.ps1], but do not treat process-marker absence as release of the integration reservation. If the existing operational route cannot hold B before VERIFY, defer B’s first dispatch until A finishes integration. Do not add a scheduler or change runtime limits.

After full PASSED verification, obtain one independent implementation review APPROVE on the exact final subject. Its worker must be idle, with no concurrent tests/verifier during review. The reviewer checks all three original findings, this plan amendment, diagnostics and precedence, exact AST controls, unchanged goldens/contracts and the complete diff. Resolve findings within bounds; changed subjects require renewed verification and review.

Then:

1. Advisor issues ACCEPT_TASK against the PASSED verification and APPROVE review.
2. Controller commits exactly the five-path accepted manifest with the stated commit message.
3. Controller scans the complete outgoing range, including the separate plan commit, for publication safety. Check every added line in every outgoing commit, not merely the final tree.
4. Controller publishes the accepted commit non-force to origin/project-2-offline-data-review-corrections using the registered single-branch refspec.
5. Record verification, review, acceptance, commit and publication identities.

No integration into Stage 9 or main belongs to this task.

Record completion token P2_OFFLINE_DATA_REVIEW_CORRECTIONS_PLAN_COMPLETE only after successful acceptance, commit and publication. COMPLETE is a programme handoff, not application acceptance or proof of real-data ingestion.

Plan acceptance, the new plan commit/hash, environment readiness, dispatch resources and all runtime results remain UNVERIFIED until recorded. Any required scope expansion needs a reviewed amendment and renewed gate before execution.
