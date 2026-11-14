# Project 1: Windows process baseline correction (Stage 10 P0 prerequisite)

**Status.** Revision 2, responding to the independent read-only review `independent-review-windows-process-correction-plan-rev1`, verdict **REQUEST_CHANGES**, of revision 1 SHA-256 `fa00409e3e5e4468ac00118e7be9309b6aafcfde1f764ef1f6d45e1e51e6d63b`. Revised by the programme advisor (gpt-6.1-sol, read-only) on 2026-11-14 under the STANDING OWNER AUTHORIZATION of 2026-11-10 and OWNER RULING of 2026-11-14, section 1. Requires independent plan **APPROVE** and advisor **DELEGATED_PLAN_ACCEPTED** for revision 2 before dispatch. This document records no implementation or runtime acceptance.

## 1. DIAGNOSIS

The evidence supports one narrowly scoped Windows process correction mission. It does not establish that endpoint security, browsers or general host load caused the failures. No product defect has yet been proved to explain Run 3.

The inspected worktree is clean at `e44ef7f142dd8315d23470753d532900a753ba82`. Revision 1 has the reviewed hash. The diff from `bc05568d92155cebd58345d260d42ecf621a5d43` names only the correction-plan document. That earlier planning subject has the Stage 9 product code of `874fb51b4959ca6c3b8e5a2bc640b9af99b176f1`.

GitNexus remains `DISABLED_WITH_EVIDENCE`; source, reference and diff inspection are the applicable fallback. No files were changed during this revision. No tests, interpreter discovery, synchronization, builds or verifier were executed. Revision 1's managed-interpreter discovery encountered a uv cache-access failure; interpreter readiness remains **UNVERIFIED**. Some read-only PowerShell inspections emitted a filesystem-provider initialization warning; the requested source and evidence reads completed.

Controller records inspected for this revision include `evidence/p0/SUMMARY.md`, the Run 3 summary, the two historical artifact-guard verifier logs and their `VERIFIER_RUN` subject records. These establish recorded outcomes and subject identities; they do not independently establish the underlying runtime causes. Turn balances, Workstream registration, controller admission and current executable readiness still require operator confirmation.

### Relevant contracts

The distinction between a timeout and an observed exit is central:

- `LaunchedProcess.wait` promises an exit value once the handle is signalled, otherwise `None`: `src/crypto_lab/process_supervision/ports.py:182`.
- Production implements that distinction before reading the native exit code: `src/crypto_lab/process_supervision/windows_process.py:383`.
- Inspection reports `ABSENT` for a signalled process object and `ALIVE_MATCHING` for an unsignalled object with the matching creation identity: `src/crypto_lab/process_supervision/windows_process.py:158`.
- Neither operation promises that an arbitrary Python child finishes starting and exiting within ten seconds.

Cleanup promises concern resources acquired or owned by the operation. A whole-pytest-process count also includes unrelated resource lifetimes. Replacing that proxy is authorized only under the proof-preservation conditions in section 3; incomplete accounting would weaken the established behavior.

### Recorded baselines

The controller's P0 summary identifies all three baseline subjects as `bc05568d92155cebd58345d260d42ecf621a5d43`:

| Run | Recorded conditions | Recorded result |
|---|---|---|
| 1 | Concurrent controller testing | FAILED: hashing timing property; 10,527 passed, 2 skipped |
| 2 | Run alone; no shared host lock | FAILED: tree-termination/inspection handle equality; 10,527 passed, 2 skipped |
| 3 | Owner-authorized additional run; shared host lock, readiness accepted, stable clean subject | FAILED: natural-exit precondition and PID-line readiness; 10,526 passed, 2 skipped |

All three remain **FAILED**. Their reported coverage was 98.67 percent against the configured 90-percent floor. Package build, schema-distribution check and Git-whitespace check were **NOT_RUN** after the test-suite failure. No fourth unchanged complete baseline is authorized.

The wider failure census below includes earlier process-test occurrences as well as P0. It must not be represented as nine failures on one unchanged subject.

### Failure-by-failure findings

Here, **(a)** denotes a possible production defect, **(b)** an unmet fixture/precondition, and **(c)** an inadequate or timing-dependent observation method.

| Recorded failure | Diagnosis and limits | Evidence and decisive observation |
|---|---|---|
| `test_strategy_hashing.py::test_an_unmutated_reload_is_identical_rather_than_merely_equal_to_itself` | **(c); functional defect not demonstrated.** P0 Run 1 reported Hypothesis inconsistent execution times: 303.90 ms against a 200 ms deadline, then 157.37 ms. Concurrent testing is established; its causal contribution is **UNVERIFIED**. | The property performs independent loads and compares identity/hash behavior: `tests/property/test_strategy_hashing.py:732`. Loading includes decoding, strict construction, graph validation and identity construction: `src/crypto_lab/strategy/loader.py:290-324`. Preserve the failing example in controller evidence only. Run the unchanged property serially; apply the latency-only disposition below if no functional mechanism is established. |
| `test_windows_process.py::test_the_handle_count_settles_to_the_exact_baseline_or_fails_at_the_bound` | **(b)/(c).** Its deterministic injected-counter checks are substantive; its final live-table check reintroduces unrelated resource lifetimes. The exact historical failing assertion remains **UNVERIFIED**. | `tests/unit/process_supervision/test_windows_process.py:2666-2676`; every live count invokes collection at `:539`. Obtain its assertion and settle record. Preserve the deterministic exact-counter negative and positive controls. |
| `test_windows_process.py::test_terminate_tree_and_inspection_leave_the_handle_table_unchanged` | **(c); an operation-owned leak remains possible.** P0 Run 2 recorded 508 handles against a baseline of 707, a decrease of 199. This neither proves an owned leak nor excludes one concealed by unrelated closures. | Three checkpoints share a baseline taken with retained launch resources: `tests/unit/process_supervision/test_windows_process.py:1782-1803`. The helper sees only totals at `:450`. Temporary inspection and descendant handles close in production `finally` paths: `src/crypto_lab/process_supervision/windows_process.py:179`, `:287`. Identify the failed checkpoint and every acquisition lifetime. |
| `test_windows_process.py::test_an_open_process_failure_at_launch_is_an_open_process_launch_failure` | **(c)** if only equality failed; **(a)** if abandonment left a child or resource. The occurrence's exact failing assertion remains **UNVERIFIED**. | `tests/unit/process_supervision/test_windows_process.py:1969-1982`. Open failure abandons the suspended child at `src/crypto_lab/process_supervision/windows_process.py:620`; abandonment suppresses bounded-wait timeout at `:524`. Capture child identity, wait outcome, both pipes, temporary resources and retained `Popen` handle lifetime. |
| `test_windows_process.py::test_a_launch_failure_leaves_no_child_and_no_extra_handle` | **(c)** is plausible; actual occurrence remains **UNVERIFIED**. A kernel32-seam-only ledger cannot establish this case. | Missing-executable launch at `tests/unit/process_supervision/test_windows_process.py:1657-1666`; production `Popen` and exception mapping at `src/crypto_lab/process_supervision/windows_process.py:588-601`. Observe standard-library acquisitions and exception-path releases before `Popen` returns or raises. |
| `test_windows_process.py::test_terminating_an_already_exited_root_reports_no_failure` | **(b); underlying reason UNVERIFIED.** P0 Run 3 failed before termination because the root inspected `ALIVE_MATCHING`. A first wait of `None` permits that observation. A first wait of `0` followed by matching-live inspection is anomalous and requires investigation. | Test at `tests/unit/process_supervision/test_windows_process.py:949`; oracle at `:433-447`; existing evidence at `:594`. Obtain the first wait return, elapsed time, fresh presence, descendant snapshot and captured resume result. |
| `test_windows_process.py::test_cancel_read_unblocks_a_reader_whose_pipe_a_grandchild_still_holds` | **(b); startup latency or a launch defect remains UNVERIFIED.** The PID-line failure preceded reader construction, so it did not exercise cancellation. | Nested readiness chain at `tests/unit/process_supervision/test_windows_process.py:234-242`; bounded read at `:548-559`; PID helper at `:569`; failing setup at `:983`. Capture phase, identities, descendants and resume result without adding observation windows. |
| `test_windows_api.py::test_the_descendant_walk_of_this_process_is_empty_and_leaks_no_handle` | **(c)** for aggregate equality; **(b)** if the empty-tree prerequisite failed because an owned descendant survived. Exact historical assertion **UNVERIFIED**. | `tests/unit/process_supervision/test_windows_api.py:368-374`; live counter at `:146`. Snapshot/candidate handles close in `src/crypto_lab/process_supervision/windows_api.py:554`, `:591`. Preserve the empty-descendant assertion independently of accounting. |
| `test_windows_api.py::test_a_failed_job_limit_closes_the_new_job_and_raises_with_its_number` | **(c)** is plausible; missing exact-job closure or wrong native error would be **(a)**. Historical failing assertion **UNVERIFIED**. | `tests/unit/process_supervision/test_windows_api.py:519-529`; production cleanup at `src/crypto_lab/process_supervision/windows_api.py:421`. Record the real created job, its successful release and the exact function/error number. |

### Artifact-guard subject correction

The two recorded failures of `tests/unit/artifacts/test_artifact_store.py::test_the_guard_literals_moved_to_the_task_four_sizes` were on dirty Stage 9 candidates:

| Verifier / task | Recorded HEAD and candidate digest | Failure |
|---|---|---|
| `verify-e05fd6e2a075` / `S9-T5-attempt-04` | HEAD `d4c65d4cdffb0319010fd1738e7d034ae77f5231`; digest `7e98093270282a386558dc42945098b3e9f36cc82652b31fa236276fa9d8df3b` | Inventory 129 against stale expected 125 |
| `verify-7aacbc99e932` / `S9-T7-attempt-03` | HEAD `ab3b6de4a0b53c6bd0afcbfcd6f9a1bb4087243c`; digest `5833397136bc492467b78a8768f5ee154237ff61b4002ba618dfe12e1171e15c` | Inventory 135 against stale expected 132 |

Sources are the controller's `state/journal.jsonl` subject records and corresponding `evidence/mission/verifier/<run-id>/verify.stdout.log` files.

These were not failures on the unchanged Stage 10 base. On the inspected `e44ef7f` subject, the guard expects the current 135 source files, 30 roots, 13 deferred names and 135 package modules: `tests/unit/artifacts/test_artifact_store.py:2050-2065`. Preserve those bytes. Require an explicit focused **PASS** on the corrected candidate; static agreement is not a newly executed test result. This guard remains outside the write bound.

### Production lead requiring investigation

`resume_initial_thread` warrants investigation before attributing Run 3 to scheduling:

1. `_first_thread_of` returns the first snapshot entry matching the PID: `src/crypto_lab/process_supervision/windows_api.py:500`.
2. `resume_initial_thread` rejects the failure sentinel but accepts a previous suspend count of zero: `src/crypto_lab/process_supervision/windows_api.py:521`.
3. Its documented reasoning assumes that the suspended new process has exactly one thread: `src/crypto_lab/process_supervision/windows_api.py:32`.

Neither Toolhelp ordering at the failed launch nor an endpoint-software explanation is established. Record the selected thread and actual `ResumeThread` previous count. Do not repeatedly resume arbitrary threads.

At natural-exit or PID-line timeout, also record `descendants_of(root)` using the root's verified creation identity. A launcher that never resumed may have no interpreter child. This and the captured previous suspend count are discriminating observations, not proof by themselves.

The jobless fixture has a separate ownership gap: the sleeper is adopted only after the PID read succeeds, while an intermediate parent may already have exited. See `tests/unit/process_supervision/test_windows_process.py:665`, `:983`. Partial setup must retain enough ownership to clean every descendant.

## 2. SELECTION

Select **one Stage 7 corrective mission: diagnose and correct Windows launch-fixture synchronization and operation-owned resource verification**.

Use **Workstream A**, which owns these modules and tests. Workstream B's reported idle 85 turns and zero deferrals confer neither product-write ownership nor a budget transfer. An independently admitted reviewer may use available review capacity.

Retain the provisional **12–24 advisor-turn** estimate. Against revision 1's supplied A balance, that leaves approximately **131–143** turns, which does not preserve Stage 10's conservative 155-turn reservation. These are planning figures, not freshly verified balances. Confirm and journal current capacity before correction dispatch, then reforecast Stage 10 before its implementation dispatch. No ceiling increase is assumed.

The correction must:

- Prove exact acquisition, successful release and explicit retention of every operation-owned resource.
- Preserve real Windows execution, exact native errors, child absence, PID-plus-creation identity, job membership, cancellation and reader-end assertions.
- Establish ownership before an intermediate fixture parent may exit, using the permitted acknowledgement channel below.
- Keep timeout failures distinct from observed natural exits.
- Correct production wherever focused evidence demonstrates defective resume, abandonment, ownership or cleanup.
- Preserve the existing observation budget on every affected path.

For each path from launch to an assertion, **neither the number of bounded observations nor their total permitted allowance may exceed that path on `e44ef7f`**. An existing ten-second observation remains ten seconds in total; adding phases does not create additional ten-second windows. Step 2 requires a checkable before/after path inventory, including paths that already contain multiple distinct observations.

No longer bound, arbitrary delay, retry-until-green loop, skip, xfail, tolerance or lowered threshold is selected. Cleanup retains its existing committed production waits and identity rules.

The mission must not change launcher/verifier bytes, dependencies, coverage settings, Hypothesis settings, generated example domains/counts, production deadlines, existing skip permissions, schemas, migrations, Stage 10 implementation or unrelated guards.

The hashing property remains unchanged. Its failing example belongs only in controller evidence: no `@example`, decorator or other edit to `tests/property/test_strategy_hashing.py` is authorized.

## 3. OWNER-DELEGATED TECHNICAL DECISIONS

These are model decisions under delegated authority, not new owner rulings.

### R2 authority and the exact proof-method replacement

R2 is a human ruling of 2026-09-18/19, reflected in `tests/unit/process_supervision/test_windows_process.py:54-56`, `:2667-2671` and commit `e9bcd8e19563f6ececdf5f683a561cdf36caa712`. It must not be superseded by model preference alone. The Stage 10 plan reserves acceptance changes to the owner at `docs/superpowers/plans/2026-08-10-project-1-cli-composition-end-to-end-acceptance-implementation-plan.md:67-71`.

The authority for this narrow replacement is the later **OWNER RULING of 2026-11-14, section 1**, which authorizes diagnosis/correction while requiring preservation of “the behavior the affected tests are intended to establish.” It permits replacing the defective proof method only when the replacement preserves that behavior. The standing technical-decision classes supply no independent authority to weaken R2.

The established resource behavior remains: failed launch leaves no owned child or resource; inspection and termination leak no temporary resource; intentionally retained launch resources keep their established ownership/lifetime; cleanup releases everything due at its boundary. Required unaccounted resources remain **exactly zero**.

The R2-related changes permitted by this plan are limited to:

1. The method description in the module docstring at `test_windows_process.py:54-56`.
2. The live-table default/use of `_settled_handle_count` at `:450-470`.
3. Live equality checkpoints at `:1660-1666`, `:1794-1803` and `:1973-1982`.
4. The real-table subcase at `:2676` in `test_the_handle_count_settles_to_the_exact_baseline_or_fails_at_the_bound`.
5. The R2-only caller/body pins within `test_the_ruling_oracles_are_used_exactly_where_the_ruling_names_them`, `:2679-2807`, replacing their obsolete live-counter dependency with complete-accounting pins.
6. Corresponding API live equalities listed explicitly in Step 3.

Keep the injected-counter proof referred to as “R2 pins 6 to 8”: a constant one-handle excess fails at expiry, later exact equality succeeds, and no tolerance is admitted. Replace its live-table subcase with deterministic evidence rather than another whole-process assertion.

Complete accounting is at least as strong for the established resource behavior only if it covers every acquisition route, detects each planted leak class, distinguishes handle reuse, verifies real successful closes and covers retained lifetimes. It additionally rejects an owned leak concealed by unrelated closure. The reviewer must establish these conditions before approving removal of any live equality.

If completeness or behavioral equivalence cannot be demonstrated, **do not replace the affected proof**. Report the unresolved authority/equivalence issue to the controller. Any proposed acceptance relaxation requires owner confirmation before dependent work proceeds.

| Class | Decision | Preserved guarantees |
|---|---|---|
| `correction_ordering` | Correction precedes Stage 10 P0 satisfaction and implementation dispatch. | Preserve all failed baselines; require a genuine reviewed correction and its own fresh PASSED complete verification. |
| `implementation_interpretation`, bounded by the explicit owner ruling above | Replace live aggregate resource proof only at the enumerated sites with complete operation-owned accounting. | Exact zero unaccounted resources, real releases, retained lifetimes, native errors and child absence; no tolerance. |
| `implementation_interpretation` | Synchronize fixture ownership and distinguish failed setup from tested behavior. | Existing observation budgets, exact natural exits, identity-safe absence, blocked-reader cancellation and `CANCELLED` versus EOF. |
| `task_sequencing` | A owns the correction; controller owns admission and release. | No implicit ownership transfer, budget transfer or Stage 10 scope expansion. |

The seven permitted decision classes are listed at `docs/superpowers/plans/2026-08-10-project-1-cli-composition-end-to-end-acceptance-implementation-plan.md:447-450`.

A new kernel32 name is **not authorized by this plan**. Changing the reviewed 22-name surface, `_API_NAMES`, its reviewed-surface pin or the error contract requires an exact reviewed plan amendment before implementation, even though the files are in bound. An owner-held security or acceptance change additionally requires owner authorization. In particular, a `ResumeThread` previous count of zero supplies no failing Win32 error number: do not invent one or use stale `GetLastError()` as its explanation.

No publication-destination, floor-file, dependency, network or budget exception is taken.

## 4. THE PLAN

=== PLAN BEGIN ===

### Task 1 - Diagnose and correct Windows process baseline failures

**Files modified.** `tests/unit/process_supervision/test_windows_process.py`, `tests/unit/process_supervision/test_windows_api.py`, `src/crypto_lab/process_supervision/windows_process.py`, `src/crypto_lab/process_supervision/windows_api.py` (the maximum worker bound)

Create no repository files. Test fixture files under pytest temporary roots and controller-owned execution evidence are permitted runtime artifacts, not additions to the repository manifest.

These four paths are the maximum worker bound. Production changes require a demonstrated defect and focused semantic RED evidence. Exclude unchanged paths from the final manifest. No fifth path is justified or authorized.

**Subject and placement.**

Use Workstream A and a registered corrective branch whose clean dispatch parent and worker diff base are exactly:

the accepted revision-2 plan commit recorded as the mission gate's base_commit (its product tree is identical to `e44ef7f142dd8315d23470753d532900a753ba82`)

Preserve both accepted planning documents and all three failed P0 records. Do not compute the worker manifest against `bc05568d`: that would incorrectly include the correction-plan document. Record revision 2 approval in controller-owned evidence without adding it to the worker manifest. A changed dispatch parent requires explicit reconciliation before dispatch.

Freeze concurrent product work. The correction is a Stage 7 prerequisite mission, not Stage 10 implementation. Record its budget separately; the Stage 10 estimate excludes corrective missions: `docs/superpowers/plans/2026-08-10-project-1-cli-composition-end-to-end-acceptance-implementation-plan.md:5110`.

**Role boundary.**

The operator/controller provisions Step 1. The worker performs Steps 2–4 and returns a frozen candidate plus evidence report. The controller commissions independent review, orders full verification and performs Step 6. Review corrections may return narrowly scoped work to the worker.

The worker must not manufacture review approvals, verifier outcomes, advisor decisions, publication receipts or the completion token.

**Step 1 — Establish authority, evidence, prerequisites and guard constraints.**

The operator/controller must:

1. Confirm revision 2's independent plan APPROVE and advisor DELEGATED_PLAN_ACCEPTED, exact dispatch parent, branch registration, clean subject, capacity and four-path bound.
2. Confirm managed CPython with:

   ```powershell
   uv python find --managed-python --system --no-python-downloads 3.12
   ```

   Stop if unavailable. Resolve the earlier cache-access issue without substituting system Python or acquiring an interpreter.
3. Confirm offline lock and synchronization prerequisites through existing `lock-check` and `sync` operator profiles. Acquire nothing; add no profile or exception.
4. Preserve complete P0 failure records, the Hypothesis example, historical process-failure assertions and available `termination-shapes` evidence. Keep the example in controller evidence only.
5. Obtain Run 3's first-wait return, elapsed time and inspected presence, if retained; distinguish missing evidence from a negative observation.
6. Identify Run 2's failed settle checkpoint and retain the exact 508-versus-707 record.
7. Preserve the two artifact-guard subjects identified in section 1; do not associate them with P0.

Admit only these six worker profiles: `pytest-focused`, `ruff-format-all`, `ruff-check-all`, `mypy-all`, `schema-generate-check`, `migration-check`. Bootstrap operations and the complete verifier remain operator/controller actions. Never invoke `uv run` directly or dot-source the launcher.

**Closed-world must-not list.**

The worker must inspect the following guards before editing and preserve them. They are constraints, not extra writable paths:

- **Production gains no import root.** `windows_process.py` retains exactly `{__future__, collections, contextlib, subprocess, typing, pydantic, crypto_lab}`. `windows_api.py` retains exactly `{__future__, contextlib, ctypes, typing, pydantic, crypto_lab}`. In particular, add no threading, queue, time, os or ctypes import to `windows_process.py`, and no subprocess import to `windows_api.py`.
- **The launch shape is untouched.** Keep the single production `subprocess.Popen` call, its argument array and exact keywords, including `stdin=DEVNULL`, empty environment, pipes, flags and no shell. Add no second production `subprocess.*` call.
- In either bounded test module, add no actual `import subprocess` or `from subprocess ...`, and make no test-code call through a local name `subprocess`. Test-local instrumentation must go through `windows_process_module.subprocess`. Existing embedded child-program strings remain subject to their existing rules.
- Never introduce the literal text `os.system` anywhere in either test module, including comments and strings.
- Put no `sandbox` text anywhere in either production file. Their module docstrings must contain none of `time.time`, `random.`, `datetime.now`, `uuid4(`, `os.environ`, `import random`, `import doubles`, or `from doubles`.
- Preserve `a cleanup mechanism, never a security boundary` in `windows_process.py` and `not earlier than` in `windows_api.py`.
- Preserve production `__all__`, structure sizes, the single lazy `_KERNEL32` slot, kernel32-only binding and the reviewed 22-name API surface.
- Preserve all environment, infrastructure, ambient-clock, filesystem, shell and process-import confinement rules. Add no ambient environment inspection or new import-time effects.
- Add no test class defining both `get` and `get_many`: it would change an unrelated exact census.
- Change no source-file, module, import-root, deferred-name or subprocess-importer inventory.

Relevant out-of-bound guards:

| Guard | Constraint |
|---|---|
| `tests/safety/test_stage7_boundaries.py:147-159`, `:574-648` | Root confinement, environment/filesystem scans, exactly one Popen with the reviewed shape, exactly one subprocess call target |
| Same file `:677-705`, `:780-789` | Scan census, restricted wording/docstrings, descendant-creation phrase |
| `tests/safety/test_stage5_boundaries.py:107-130`, `:474-490`, `:578-640` | Infrastructure confinement, double-class census and planted import controls |
| `tests/safety/test_stage3_boundaries.py` | Closed 135-file inventory, 30 roots, os confinement, 13 deferred names and environment scan |
| `tests/safety/test_stage6_boundaries.py:106-122`, `:373-413` | Exactly 13 subprocess importers and whole-test-tree shell-text census |
| `tests/unit/test_package_layout.py` | Closed package inventory and fresh-import side-effect probe |
| `tests/unit/artifacts/test_artifact_store.py:2030-2065` | Current 135/30/13/135 census |
| `tests/architecture/test_package_import_boundaries.py:488` | Process-supervision dependency boundary |

In-bound structural guards also remain substantive:

- `test_windows_process.py:2679-2807`: preserve the existing nine `_exited` callers, exact four-entry positive `.wait` set, dictated-reason callers, one `_absent` kernel wait and `_exited` shape. Change only the explicitly authorized R2 accounting pins.
- Do not add keyword-only `.wait(timeout=...)` calls in the test module: the existing AST pin destructures one positional argument.
- `test_windows_process.py:2888-2953`: preserve no test-code sleep, skip, xfail or coverage exclusion; `_WAIT_BOUND_SECONDS == 10.0`; no `_wait_until` or `_PAUSE` in cleanup, `ended`, `_absent`, `_native_exit` or `terminate_owned`.
- `test_windows_process.py:1160-1190`, `:1320`, `:1355-1390`, and `test_windows_api.py:387-463`: preserve launch, exports, imports, lazy binding and reviewed API constraints.

Do not weaken a guard to admit instrumentation. If an essential correction cannot satisfy these constraints, stop dependent implementation and seek an exact amended plan.

Run focused work serially under shared-host discipline. Do not run another unchanged complete baseline.

**Step 2 — Obtain focused RED and discriminate mechanisms.**

**Canonical affected selector list S.** The following command is the sole explicit list for both the initial unchanged RED attempt and the final affected-selector rerun after correction. Execute it verbatim at both points and preserve every result. It includes all eight recorded process failures and the hashing property. Keep every original test name; additions supplement them.

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/unit/process_supervision/test_windows_process.py::test_the_handle_count_settles_to_the_exact_baseline_or_fails_at_the_bound tests/unit/process_supervision/test_windows_process.py::test_terminate_tree_and_inspection_leave_the_handle_table_unchanged tests/unit/process_supervision/test_windows_process.py::test_an_open_process_failure_at_launch_is_an_open_process_launch_failure tests/unit/process_supervision/test_windows_process.py::test_a_launch_failure_leaves_no_child_and_no_extra_handle tests/unit/process_supervision/test_windows_process.py::test_terminating_an_already_exited_root_reports_no_failure tests/unit/process_supervision/test_windows_process.py::test_cancel_read_unblocks_a_reader_whose_pipe_a_grandchild_still_holds tests/unit/process_supervision/test_windows_api.py::test_the_descendant_walk_of_this_process_is_empty_and_leaks_no_handle tests/unit/process_supervision/test_windows_api.py::test_a_failed_job_limit_closes_the_new_job_and_raises_with_its_number tests/property/test_strategy_hashing.py::test_an_unmutated_reload_is_identical_rather_than_merely_equal_to_itself -q
```

A passing rerun is not RED evidence and does not establish a correction. Do not repeat unchanged runs to obtain either a failure or a pass.

**Observation-budget inventory.**

Before edits, record in controller evidence a path table against `e44ef7f`. For every affected launch-to-assertion path, identify:

- Each positive blocking observation, its call site, count and permitted allowance.
- Nested readiness reads, thread joins, child-side acknowledgement polling and any applicable existing termination/cleanup waits.
- The total permitted allowance along the path, counting overlapping work once only when the overlap is demonstrated.

Require, for every corresponding revised path P:

`N_revision2(P) <= N_e44ef7f(P)` and `B_revision2(P) <= B_e44ef7f(P)`.

Every existing ten-second observation remains capped at ten seconds in total. In particular:

- Launch to the natural-exit precondition retains the one ten-second `_exited` wait; do not insert a readiness wait before it.
- Launch to the PID-line assertion retains one ten-second bounded read covering its nested startup chain; do not split the chain into independently bounded reads.
- The pipe-holder test already has distinct PID-read and natural-exit observations, followed by existing reader joins. Its complete path must not gain another observation or greater summed allowance.
- Progress messages, helper boundaries, acknowledgement polling and timeout diagnostics must not restart a deadline.
- Cleanup retains its existing per-identity waits and at-most-once termination rules. Diagnostic collection adds no wait.
- New semantic controls must not introduce extra observations into existing behavior paths.

The independent reviewer must compare this table with the source and diff. Passing the existing structural pins alone does not establish this rule.

**Test-local evidence.**

Use transparent spies/proxies through the existing seams. Production gains no instrumentation import or extra launch.

Extend `_ShapeEvidence` to retain, by test and launch identity:

- Launch/readiness phase, first wait return, elapsed observation time and fresh inspected presence.
- Selected resume-thread identifier and the actual `ResumeThread` previous suspend count captured from the real call.
- At a natural-exit or PID-line timeout, `descendants_of(root_pid, root_creation_time)` or the precise failure to obtain that snapshot.
- Known owned identities, partial setup state, reader state and relevant acquisition/release records.

Capture resume evidence at the real launch call; do not invoke `ResumeThread` again to obtain evidence. Timeout diagnostics must not mask the original failure. Do not inspect environment values, credentials, unrelated process memory or unrelated command lines.

Account for real acquisitions, successful closes, transfers and deliberate retention. Distinguish the retained `Popen` handle from temporary handles; its lifetime contract is at `src/crypto_lab/process_supervision/windows_process.py:317-320`.

**Latency-only disposition.**

If decisive evidence shows first wait `None` with `ALIVE_MATCHING`, with no demonstrated resume, ownership or cleanup defect, record the occurrence as **UNRESOLVED — latency-only evidence**. Apply the same disposition to a PID-line timeout supported only by startup latency and to a hashing deadline recurrence without a functional defect.

Keep fail-on-timeout and all existing deadlines. Never re-bound, suppress the deadline, force the natural-exit precondition, or call the occurrence resolved because a later run passes.

Report this disposition to the controller **before the complete verifier**. The controller must resolve the diagnosis/correction prerequisite before ordering that verifier; diagnostic improvements alone are not a genuine correction. Continue independent in-bound work where useful, but do not use a complete-verifier rerun to evade an unresolved latency-only failure.

A first wait returning an exit code followed by `ALIVE_MATCHING`, or evidence of an incorrect resume/ownership transition, follows the product-defect investigation route instead.

**Semantic RED controls.**

Add controls for:

- An operation-owned leak detected despite an unrelated handle closure.
- Balanced operation-owned cleanup unaffected by unrelated handle churn.
- Every resource class and endpoint required by Step 3.
- Missing readiness/acknowledgement with complete partial-tree and reader cleanup.
- Exhaustive classification of the reviewed API surface and coverage of every handle creator.

Use these proposed additional selectors, recording any parameter IDs in the evidence report:

- `tests/unit/process_supervision/test_windows_process.py::test_an_operation_owned_leak_is_detected_despite_unrelated_handle_closure`
- `tests/unit/process_supervision/test_windows_process.py::test_unrelated_handle_churn_does_not_fail_balanced_operation_cleanup`
- `tests/unit/process_supervision/test_windows_process.py::test_readiness_failure_cleans_the_partially_established_tree_and_reader`
- `tests/unit/process_supervision/test_windows_api.py::test_every_reviewed_handle_creator_has_resource_ledger_coverage`

Strengthen the existing `test_a_child_alive_after_the_ten_second_wait_fails_the_natural_exit_oracle` rather than adding an `_exited` caller or positive wait. Preserve the existing exact-native-exit controls and failed-job test name.

RED must expose the actual incorrect oracle or faulty transition. A missing helper/import is insufficient. Demonstrate that aggregate equality can miss a planted owned leak when an unrelated handle closes and can reject balanced ownership under unrelated churn. Reclaim planted resources after the expected assertion, including on control failure.

For any proposed production change, first add a focused semantic test reproducing the demonstrated defective transition. Record its selector and RED evidence. Do not invent a fix from the unverified resume lead.

**Step 3 — Implement the minimum correction and focused GREEN.**

**Complete resource accounting.**

The replacement ledger must cover every handle-creating API in the current `_API_NAMES`, plus standard-library launch resources:

| Required class | Acquisition coverage |
|---|---|
| Process handles | Every successful `OpenProcess`, including inspection, descendants, failure cleanup and retained controller handles |
| Job handles | Every successful `CreateJobObjectW`, including setup failure and retained-job ownership |
| Snapshot handles | Every successful `CreateToolhelp32Snapshot`, for both process and thread snapshots and all enumeration exits |
| Thread handles | Every successful `OpenThread`, including resume and I/O cancellation |
| `Popen` pipes | Both stdout/stderr read ends and temporary/child-side pipe endpoints acquired during construction, including constructor failure |
| `Popen` process handle | `_handle` acquisition, abandonment and deliberate retention through the established object lifetime |

Also classify auxiliary resources acquired by the standard-library construction path, including DEVNULL descriptors/handles and temporary process/thread handles where present. A constructor exception before a wrapper returns does not exempt those acquisitions.

Inspect the selected managed CPython 3.12 implementation read-only to choose the necessary seams. A wrapper that observes only a successfully returned `Popen` is insufficient. Instrumentation must use `windows_process_module.subprocess` and its reachable implementation seams; add no subprocess importer or production import root.

Requirements:

- Partition all current `_API_NAMES` into explicitly reviewed creators and non-creators. Pin exhaustiveness and disjointness against the actual reviewed surface. Any added API name must fail until classified; any handle creator must have ledger coverage and a planted-leak control.
- Keep the existing reviewed-surface pin. Do not make the new completeness check tautological by deriving both its expected coverage and observed coverage from the same list.
- Pin the separate standard-library acquisition/close routes used by the supported launch path, including exception paths.
- Record acquisition generations, resource class, owner, transfer, successful real close and permitted retention. Numeric handle reuse must not merge lifetimes.
- Record release only after the real close succeeds. An attempted or fabricated successful close is insufficient.
- Do not retain resource-owning objects merely for observation or release a planted leak before the assertion that must detect it.
- Require exactly zero unaccounted resources at each relevant boundary. A retained resource needs an explicit owner and verified eventual release.
- Preserve the `Popen` handle until its established lifetime boundary; do not close it early and weaken PID reservation.
- Exercise real APIs in positive cases. Keep descendant absence and cleanup-failure reporting independent of the ledger.

Plant at least one safely reclaimed leak for each of the six classes above. Parameterize pipe coverage for both streams and their applicable temporary endpoints, and snapshot coverage for both snapshot kinds. Exercise both pre-return constructor failure and post-creation abandonment. Demonstrate detection despite cancelling unrelated closure, and demonstrate that balanced ownership passes under unrelated churn.

If any acquisition class cannot be observed completely within this bound, retain the affected old assertion and report the blocker. Do not substitute a seam-only partial ledger.

**Every live whole-process equality site and disposition.**

All references below are on dispatch parent `e44ef7f`; keep the named tests:

| Site | Required disposition |
|---|---|
| `test_windows_process.py:1660-1666`, `test_a_launch_failure_leaves_no_child_and_no_extra_handle` | Replace live equality with complete failed-construction accounting, no retained resource and no owned child. |
| `test_windows_process.py:1794-1803`, `test_terminate_tree_and_inspection_leave_the_handle_table_unchanged` | Replace all three live checkpoints with per-operation exact accounting. Distinguish pre-existing retained launch resources from temporary acquisitions; preserve tree/report/absence assertions and verify eventual retained-resource release. |
| `test_windows_process.py:1973-1982`, `test_an_open_process_failure_at_launch_is_an_open_process_launch_failure` | Replace equality with complete abandonment accounting, including `Popen` resources; preserve exact error mapping and independent descendant absence. |
| `test_windows_process.py:2676`, `test_the_handle_count_settles_to_the_exact_baseline_or_fails_at_the_bound` | Remove the real-table subcase. Keep the test name and deterministic exact-counter expiry/equality controls. |
| `test_windows_api.py:372-374`, `test_the_descendant_walk_of_this_process_is_empty_and_leaks_no_handle` | Replace live equality with exact snapshot/candidate-handle accounting; retain the independent empty-descendant assertion. |
| `test_windows_api.py:522-529`, `test_a_failed_job_limit_closes_the_new_job_and_raises_with_its_number` | Require successful closure of the exact created job and zero outstanding operation resources; retain exact function and error 87. |
| `test_windows_api.py:553-563`, `test_a_failed_process_snapshot_walk_raises_or_is_empty_by_its_number` | Account for both real snapshots independently; preserve error 87 and the error-18 empty-result branch, proving both snapshots released. |

Update only the R2-related structural pins described in section 3. Keep deterministic settling-helper semantics exact. A live count may remain diagnostic, but must neither establish nor veto resource-cleanup success.

**Permitted fixture acknowledgement channel.**

Keep production stdin `DEVNULL` and the entire launch shape unchanged.

For the affected jobless spawner, use a test-only sentinel in its existing `tmp_root` cwd:

1. The child establishes sleeper readiness, prints the existing PID line and flushes it.
2. The intermediate parent remains alive while the test binds PID-plus-creation identities and adopts the required descendants.
3. Only after adoption does the test create the agreed sentinel under that same temporary cwd.
4. The inline `-c` program checks for the sentinel in short slices, such as 0.1 seconds, within the existing observation allowance. This is a protocol wait, not a delay intended to make the test pass.
5. The parent exits naturally only after acknowledgement. Missing acknowledgement cannot establish successful setup.

The sentinel is unique to the fixture root and absent before launch. Use no environment variable, stdin pipe, production filesystem operation or extra readiness read. The existing PID-line count and flush behavior remain intact.

Child-side polling must have a fixed, non-renewing deadline compatible with the Step 2 path table. On acknowledgement failure, the intermediate parent must remain available for owned-tree discovery and fixture cleanup rather than exit and strand unadopted descendants. Failure remains a test failure; it creates no extra observation window.

Before destructive partial-setup cleanup, capture reachable descendant identities while the intermediate parent is still owned and alive. Terminate through the existing identity-safe paths at most once per tree. Cancel and join setup readers within existing cleanup allowances; do not add a fresh ten-second join.

Preserve the pipe-holder sequence: exact natural root exit, another live owned process holding the write end, reader demonstrably blocked, successful cancellation, ended reader with `ReaderEnd.CANCELLED`, and closed resources. Cancellation remains distinct from EOF: `src/crypto_lab/process_supervision/readers.py:91`.

**Unbounded-read disposition.**

The existing `launched.stdout.readline()` sites at `test_windows_process.py:1034`, `:1282`, `:1303` and `:1790` are not authorized for conversion into new independently bounded reads. Preserve their existing line counts and fixture protocol. Do not replace them with additional ten-second failure points.

If evidence identifies one as requiring a distinct behavioral correction, report it for an exact plan amendment with its observation-budget consequences. Its mere presence does not authorize blanket wait changes.

**Production correction.**

Correct a demonstrated resume, abandonment, ownership or cleanup defect only within the two production files and all preserved guards. A new API name, changed launch contract, altered error semantics, fifth path, floor file or other authority exception requires an exact revised plan first.

Do not fabricate a native error for a non-failing API result. Do not resume arbitrary threads repeatedly or force termination to manufacture natural exit.

Run the new controls RED then GREEN through `pytest-focused`, recording exact selectors and parameter IDs. Run any demonstrated production-defect selector the same way. Then execute **canonical selector list S verbatim** for the final affected-selector rerun.

Record why the correction addresses each established mechanism. Better diagnostics alone do not close failing behavior. Apply the latency-only disposition before proceeding to full verification.

**Step 4 — Run regression and worker quality checks; return the candidate.**

Run affected modules, supervision integration, contracts, unchanged hashing properties and boundary regressions serially:

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/unit/process_supervision tests/integration/process_supervision tests/contract tests/property/test_strategy_hashing.py tests/safety tests/architecture tests/unit/test_package_layout.py tests/unit/artifacts/test_artifact_store.py::test_the_guard_literals_moved_to_the_task_four_sizes -q
```

This includes the previously omitted failed-snapshot-walk test through its complete module. Record an explicit PASS for the unchanged artifact-guard selector on the corrected subject.

Keep the hashing property and all its settings unchanged. A latency-only recurrence remains UNRESOLVED and follows Step 2.

Then run:

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-format-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-check-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 mypy-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 schema-generate-check
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 migration-check
```

`ruff-format-all` performs `ruff format --check .`; it does not apply formatting. Make any required formatting corrections manually, only within the four-path bound, then rerun the affected check.

Report every warning, skipped check, failure and unrun gate. Do not repair unrelated files. Focused runs with cleared addopts provide no acceptance-coverage evidence.

**Worker terminal deliverable:** the frozen candidate and evidence report, containing dispatch parent, exact changed-path manifest, candidate digest, patch, canonical selector results, semantic RED/GREEN evidence, complete ledger/classification and leak-control results, before/after observation-budget table, `_ShapeEvidence` records, artifact-guard result, quality-check outcomes and every unresolved failure or uncertainty.

The worker reports the last proved state and requests controller review. It does not emit `WINDOWS_PROCESS_BASELINE_CORRECTION_COMPLETE`.

**Step 5 — Independently review and fully verify the frozen subject.**

The controller freezes the candidate against the mission gate's base_commit and commissions independent review.

Review must assess:

- Each recorded failure's disposition, including latency-only UNRESOLVED cases.
- Whether production was corrected wherever a defect was demonstrated.
- R2 authority, exact changed pins and preservation of established behavior.
- Exhaustive acquisition coverage, including constructor failure, pipes and retained `Popen` handle lifetime.
- Every planted-leak class, unrelated churn and handle-number reuse.
- Every listed live equality's replacement, including both failed-snapshot branches.
- The launch-to-assertion observation table against actual source and diff.
- Acknowledgement, partial-tree ownership, setup-reader cleanup and cancellation versus EOF.
- Preservation of every named in-bound and out-of-bound guard.
- Unchanged launch shape, imports, production deadlines, coverage, Hypothesis settings and skip permissions.
- Exact source, reference and diff evidence; GitNexus stays disabled.

Do not accept an unexplained Run 3 failure because another execution passes. Do not order the complete verifier while the diagnosis/correction prerequisite remains unresolved.

After review corrections and required focused revalidation, the operator runs the unchanged complete verifier through the controller's admitted serial route, with readiness, execution-identity checks and the shared host lock:

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/verify.ps1
```

Require all eleven steps to pass. Preserve warnings, skip counts and reasons, coverage data, elapsed time, all failures and every later `NOT_RUN` step.

Keep the configured 90-percent floor and measurement settings unchanged. Preserve the failed runs' reported 98.67-percent measurements and available unrounded data. Record the corrected subject's actual measured coverage without rounding down or silently lowering its applicable requirement.

**Post-verifier hygiene is part of PASSED.** After the verifier, take the approved survivor and suspended-process probes, correlated with the task's owned identities and registered command roots. Require:

- Zero task-owned surviving processes.
- Zero suspended fixture processes.
- No task-owned Stage 7 command root left behind; pytest's retained base temporary directories are excluded as documented.

Retain probe identities, times, results and attribution limits in controller evidence. Use only approved, task-scoped inspection; do not inspect unrelated process memory, command lines or environment values.

A run leaving a task-owned process or command root is not acceptance evidence whatever its exit status: `docs/development/verification.md:1018-1023`. Missing or inconclusive probes cannot be recorded as zero. Preserve pre-run hygiene evidence for comparison and investigate any survivor.

Require journalled independent **APPROVE** and controller-accepted **PASSED** full verification, including these probes, for identical subject bytes. Follow the controller's formal review order, including any required post-verifier review.

If verification fails or is interrupted, preserve evidence, later NOT_RUN steps and hygiene results; diagnose the actual failure. No unchanged-baseline retry loop is authorized.

**Step 6 — Commit, publish and release the prerequisite.**

The controller must:

1. Verify that final diff and staged paths exactly match the approved manifest against the mission gate's base_commit; exclude both planning documents, floor files and unrelated changes.
2. Create the single corrective commit on that dispatch parent, using a truthful subject such as `test: correct windows process fixture and resource proofs`, or `fix:` if production behavior changed.
3. Prove that committed content matches the independently reviewed and fully verified candidate. Record the exact parent and commit.
4. Publish through the existing authorized route to the registered corrective branch, without force, and verify the remote SHA.
5. Keep review, verification, hygiene and publication receipts in controller evidence without changing the frozen product content.
6. Record the corrected commit as Stage 10's prerequisite subject and make the implementation branch descend from it. Any combined subject with additional changes requires its own applicable verification.
7. Confirm sufficient recorded remaining capacity before Stage 10 implementation dispatch.

No new publication destination, main publication, merge or policy-floor exception is authorized.

**The corrected subject's own accepted PASSED complete verification, including post-run hygiene, is the fresh passing baseline required by the owner. Stage 10 implementation dispatch waits for that baseline, independent approval, exact commit, verified corrective-branch publication and sufficient recorded remaining capacity.** This is not Stage 10 or Project 1 application acceptance.

**Controller-only completion token.**

Only the controller may emit `WINDOWS_PROCESS_BASELINE_CORRECTION_COMPLETE`, after every gate above is satisfied, accompanied by the exact commit, parent, branch, manifest, review ID, full-verifier ID, coverage/skip/warning record, survivor/suspended-process evidence and verified remote ref.

Until then, report the last proved state and outstanding gate. This plan emits no completion claim.

=== PLAN END ===

## 5. DISPATCH READINESS CHECKLIST

- [ ] Obtain independent APPROVE and advisor DELEGATED_PLAN_ACCEPTED for revision 2's exact bytes.
- [ ] Preserve all three FAILED P0 baselines; prohibit a fourth unchanged complete baseline.
- [ ] Register the one Workstream A correction with exactly four permitted paths and dispatch parent/diff base equal to the mission gate's base_commit (the revision-2 plan commit).
- [ ] Confirm current ownership, corrective capacity and the later Stage 10 reforecast requirement; assume no transfer or increase.
- [ ] Resolve managed-Python discovery/cache access and confirm offline prerequisites without acquisition.
- [ ] Supply historical assertions, P0 evidence, the controller-only Hypothesis example and available termination-shape records.
- [ ] Record R2's human authority, the later owner's proof-preservation authorization, exact permitted pin changes and the completeness gate.
- [ ] Require complete kernel32 and `Popen` accounting, per-class planted leaks and a fail-closed coverage pin.
- [ ] Require the before/after observation-budget table and the sentinel acknowledgement protocol with unchanged launch shape.
- [ ] Admit only the six worker profiles; keep controller actions, floor files and all unrelated guards outside worker authority.
- [ ] Schedule focused execution, independent review and full verification without competing heavy work.
- [ ] Require latency-only UNRESOLVED evidence to reach the controller before ordering the complete verifier.
- [ ] Require explicit artifact-guard PASS on the corrected candidate, without editing that test.
- [ ] Verify the existing non-force corrective-branch publication route.
- [ ] Require post-verifier survivor, suspended-process and command-root probes as part of PASSED.
- [ ] Keep the worker's terminal report distinct from the controller-only completion token.
- [ ] Keep Stage 10 implementation blocked until the corrected subject's accepted fresh baseline and all release gates exist.

Revision 2 is submitted for independent plan review. Runtime diagnosis, implementation, executable readiness and acceptance remain **UNVERIFIED**.
