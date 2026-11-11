# Project 2: installed-core identity consumer check

**Status.** Proposed under STANDING OWNER AUTHORIZATION 2026-11-10, AUTONOMOUS PROGRAMME DELIVERY. NOT_READY for implementation until independent plan APPROVE, advisor DELEGATED_PLAN_ACCEPTED and dispatch prerequisites are recorded.

**Plan location.** `docs/superpowers/plans/2026-11-11-project-2-installed-core-identity-plan.md`.

**Branch and base.** Controller prepares and registers branch and worktree `project-2-installed-core-identity`, descending from published readiness commit `5de26812c2cf0fbc1ab06a4587aeddc6d44bf83b`. This preserves all four P2 slices and their readiness brief. The controller commits the reviewed plan separately; that commit becomes the implementation gate’s `base_commit`.

**Mission identity.** New mission `crypto-lab-p2-installed-core-identity`, task prefix `P2CI-T`, implementation task `P2CI-T1`. Preserve root-wide turn accounting, readiness-deferral accounting and historical task states.

## Authority, sources and consumed versions

Unprefixed sources identify the product tree at `5de26812`; its core remains the preserved `079395bec70f1deda406d0ca14b2d4bf79aaf063` source. Explicit Stage 9 references identify `874fb51b4959ca6c3b8e5a2bc640b9af99b176f1`.

- `offline_data/docs/2026-11-11-integration-readiness.md:274-290`: consumed contracts and unchanged dependency closure.
- `offline_data/docs/2026-11-11-integration-readiness.md:376-453`: installation-identity risk and permitted consumer-test solution.
- `offline_data/scripts/invoke-offline-uv.ps1:199-219`, `offline_data/scripts/invoke-offline-uv.ps1:261-331`: isolated interpreter and admitted focused-test arguments.
- `offline_data/tests/conftest.py:67-70`: existing checkout-root fixture.
- `offline_data/tests/safety/test_boundaries.py:303-310`, `offline_data/tests/safety/test_boundaries.py:874-888`: production-package census; adding this test requires no census exemption.
- `src/crypto_lab/persistence/migration_runner.py:143-154`: installed `expected_head()` observation.
- `src/crypto_lab/persistence/migrations/versions/r0001_stage8_baseline.py:30-33`: baseline revision.
- `src/crypto_lab/persistence/migrations/versions/r0002_stage9_artifacts.py:32-35` at `874fb51b`: Stage 9 revision and parent.
- `offline_data/README.md:344-358`, `offline_data/README.md:376`: established residual-carriage-return behavior and incomplete refusal-table row.

Consumed versions remain: descriptor and partition schemas `1.0.0`; hash profile `dataset-metadata/v1`; inputs `ohlcv-csv/1` and `binance-spot-kline-csv/1`; provenance `1.0.0`; container `normalized-ndjson/0.1.0`; column schema `0.1.0`; both distribution versions `0.1.0`. Existing dependency pins, locks and coverage floors remain unchanged.

### Task 1 - Bind the installed core to the offline-data checkout

**Objective.** Add a consumer test that detects stale or misbound core installations and observes the installed migration head through the existing offline pytest route. Document its limits and close the recorded refusal-table omission.

**Prerequisites.** Independent plan APPROVE and advisor DELEGATED_PLAN_ACCEPTED covering exact plan bytes and commit; registered branch, worktree and single-branch publication refspec; unique mission and gate; complete bounds; both environments synchronized offline; admitted execution profiles; available worker capacity and quiet-host resource preflight.

**Files created.** `offline_data/tests/integration/test_installed_core_identity.py`.

**Files modified.** `offline_data/README.md`.

**Writable boundary.** These two exact paths are the complete implementation manifest. The controller-owned plan commit is outside worker bounds. Use no directory bounds or patterns.

**Required behavior.**

1. Perform filesystem observations inside tests or fixtures. Import the core through the existing non-editable dependency; do not load checkout source as a substitute for the installed package.

2. Verify the running interpreter belongs to this checkout’s `offline_data/.venv`, and that the imported core package and migration runner originate in that environment’s installed package. Reject checkout-source imports, the root environment and another worktree’s installation. Derive paths from the test checkout; embed no host-specific paths.

3. Build sorted inventories of every `.py` file beneath the checkout’s `src/crypto_lab` and the installed `crypto_lab` package. Require nonempty, identical relative-path sets and exact byte equality, with SHA-256 identities available for review. Missing, extra or changed Python files fail. This covers the brief’s consumed modules and their Python import closure without importing every module.

4. Determine the required migration head from the checkout’s exact known versions inventory:

   - `__init__.py` and `r0001_stage8_baseline.py`: require `r0001_stage8_baseline`.
   - Those files plus `r0002_stage9_artifacts.py`: require `r0002_stage9_artifacts`.

   Reject any other inventory. The installed inventory must match the checkout; accepting either head independently of the checkout is forbidden.

5. Call the installed migration runner’s default `expected_head()` and require the checkout-selected head. Do not pass the checkout as `script_location`, execute migration upgrades, or create a database in this new test.

6. Emit a compact deterministic success record into retained pytest output using the existing capture fixture’s disabled context. Include repository-relative environment/package labels, module count, a documented deterministic inventory digest, migration filenames and observed head. Emit no absolute paths, environment values or file contents. The full verifier must retain this record.

7. Include isolated synthetic controls under `tmp_path` proving rejection of changed bytes at the same nominal version, missing and extra files, empty inventories, a simulated Stage 9 checkout paired with a baseline installation, an incorrect observed head, and incorrect interpreter/package binding. Include a matching positive control. Never mutate the real checkout, installed package, interpreter or migration directory to obtain negative evidence.

8. Preserve the existing registration test and goldens. On this task’s real baseline, require `r0001_stage8_baseline`. Synthetic Stage 9 controls establish checker behavior only; an actual `r0002` result remains owed by the later combined-tree route.

**README changes.**

Add a short explanation of the identity check, its focused command, retained evidence, and the distinction between checkout identity and combined-tree acceptance. Preserve the current consumed-core pin and pending-finalization statements.

Correct only the recorded `CSV_ROW_SHAPE` refusal-table omission: include wrong field count and residual carriage return in field 12 after fields 1–11 pass. State that `value_length` covers the complete logical row, including residual carriage returns and excluding the consumed LF/CRLF delimiter. Match the existing detailed prose without changing behavior.

**Exclusions.** No production-source, core-test, schema, migration, dependency, lock, launcher, verifier, conftest, committed-fixture or golden changes. No guard exemptions, threshold reductions, command profiles, environment repair/reinstallation, network, package acquisition, real data, engines, persistent registration or artifact finalization. No merge, rebase, cherry-pick, main publication or milestone recording belongs to this worker task.

If approved synchronization leaves an identity mismatch, report the exact relative mismatch and stop for controller disposition. Do not invent a rebuild command.

**Execution.** Run from the registered worktree root through the committed profiles. Operator/controller preparation, before worker activity:

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 lock-check
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 sync
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/invoke-offline-uv.ps1 lock-check
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/invoke-offline-uv.ps1 sync
```

Stop on any unavailable interpreter, package or offline-cache prerequisite; acquire nothing.

Implement the test and its synthetic controls, then run:

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/invoke-offline-uv.ps1 pytest-focused -o addopts= tests/integration/test_installed_core_identity.py tests/integration/test_sqlite_dataset_registration.py tests/integration/test_core_contract_roundtrip.py tests/safety/test_boundaries.py -q
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/invoke-offline-uv.ps1 ruff-format-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/invoke-offline-uv.ps1 ruff-check-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/invoke-offline-uv.ps1 mypy-all
```

The format profile checks only; hand-edit authorized files as needed. No direct uv, Python, pytest or product-command invocation. Leave the worker idle with exactly the two authorized changed paths.

**Commit message.** `test(offline-data): verify installed core identity against checkout`

## Verification, review, publication and completion

The controller issues VERIFY with `verification_scope=full` and `verification_targets=[]`, running these unchanged scripts in order on the same final subject:

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/verify-offline.ps1
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/verify.ps1
```

Retain every configured gate: offline lock/sync, formatting, lint, strict typing, full tests and hygiene; core schema generation, migrations, full tests, build and schema distribution. Preserve branch-coverage floors of 98.61 percent for P2 and 90 percent for the core. Report every warning, skip and failure. Sources: `offline_data/scripts/verify-offline.ps1:21-49`, `scripts/verify.ps1:19-73`, `offline_data/docs/2026-11-11-integration-readiness.md:483-514`.

Bind verification to the accepted parent, exact two-path subject digest, launcher/verifier identities and both environments. Retain the new identity success record from the full offline run. Earlier slice, readiness and Stage 9 passes do not cover this task.

At most two product implementation workers; one heavy verifier/process-test workload under `.crypto-lab-host/verifier.lock`. Keep `dispatch_wait_markers=[verify.ps1]` and give A’s authoritative verification priority. Under the current interim instruction, launch the relay only on a quiet host; any readiness or lock deferral ends the mission step. Preserve counters and limits.

After full PASSED verification, obtain independent implementation review APPROVE on the exact subject, with the worker idle and no concurrent tests/verifier. Review the origin binding, complete inventory comparison, checkout-dependent migration requirement, synthetic rejection controls, retained evidence, README changes and full diff. Any subject change requires renewed verification and review.

Then:

1. Advisor issues ACCEPT_TASK against the PASSED verification and APPROVE review.
2. Controller stages and commits exactly the accepted two-path manifest.
3. Controller scans every added line in every outgoing commit, including the separate plan commit, for publication safety.
4. Controller publishes non-force to `origin/project-2-installed-core-identity` using registered refspec `refs/heads/project-2-installed-core-identity:refs/heads/project-2-installed-core-identity`.
5. Confirm and record the remote commit plus verification, review, acceptance and commit identities.

Record completion token `P2_INSTALLED_CORE_IDENTITY_PLAN_COMPLETE` only after acceptance, commit and confirmed publication. Queue the accepted descendant as an input to the future controller integration route. Completion establishes this consumer-check handoff; Stage 9/P2 combined execution, milestone acceptance, main integration and artifact finalization remain pending.
