# Project 1: Windows process baseline correction (Stage 10 P0 prerequisite)

**Status.** Revision 1. Written by the programme advisor (gpt-6.1-sol, read-only) on 2026-11-14 under the STANDING OWNER AUTHORIZATION of 2026-11-10 (delegated planning authority) and the OWNER RULING of 2026-11-14, section 1, after three complete-verifier executions of the unchanged Stage 10 base (plan commit bc05568d over main 874fb51b) all FAILED on bounded-time process tests. The controller session added this title and status line and kept the advisor's sections verbatim; the task itself is the text between the plan markers, reproduced under section 4. Requires independent plan APPROVE and advisor DELEGATED_PLAN_ACCEPTED before dispatch. This document records no runtime acceptance.

## 1. DIAGNOSIS

The evidence supports a narrowly scoped Windows process correction mission. It does **not** establish that endpoint security, browsers, or general host load caused the failures. No product defect is yet proved to have caused Run 3.

I confirmed clean HEAD at `bc05568d92155cebd58345d260d42ecf621a5d43` and made no changes. GitNexus remains disabled. Managed-interpreter discovery failed because uv could not access its cache, so interpreter readiness is **UNVERIFIED**. I ran no tests, builds, or verifier.

The controller transcripts are supplied evidence; I could not inspect their underlying records.

### Relevant contracts

The distinction between a timeout and an observed exit is central:

- `LaunchedProcess.wait` promises an exit value once the handle is signalled, otherwise `None`: `src/crypto_lab/process_supervision/ports.py:182`.
- Production implements that distinction before reading the native exit code: `src/crypto_lab/process_supervision/windows_process.py:383`.
- Inspection reports `ABSENT` for a signalled process object and `ALIVE_MATCHING` for an unsignalled object with the matching creation identity: `src/crypto_lab/process_supervision/windows_process.py:158`.
- Neither operation promises that an arbitrary Python child will finish starting and exiting within ten seconds.

Likewise, cleanup promises concern resources acquired or owned by the operation. They do not promise that the entire pytest process’s handle count remains constant while unrelated objects are finalized.

### Failure-by-failure findings

| Recorded failure | Most likely mechanism and classification | Evidence and decisive missing observation |
|---|---|---|
| `test_strategy_hashing.py::test_an_unmutated_reload_is_identical_rather_than_merely_equal_to_itself` | **(c), timing-dependent assertion; functional defect not demonstrated.** Hypothesis rejected inconsistent execution times, rather than unequal hashes. Concurrent controller testing is a plausible contributor, **UNVERIFIED** as the cause. | The property performs two independent complete loads and asserts distinct objects with equal hashes: `tests/property/test_strategy_hashing.py:732`. Each load performs YAML decoding, strict construction, graph validation and identity construction: `src/crypto_lab/strategy/loader.py:290`. The recorded times straddle the deadline. Preserve the failing example and run this unchanged property serially through the registered profile. A serial recurrence requires measured investigation; it does not authorize deadline suppression. |
| `test_windows_process.py::test_the_handle_count_settles_to_the_exact_baseline_or_fails_at_the_bound` | **(b)/(c), an uncontrolled whole-process assertion inside an oracle test.** Its injected-counter cases are deterministic; its final real-table assertion can observe unrelated resource changes. Which assertion failed historically is **UNVERIFIED**. | The test itself documents drift from earlier objects being finalized, but finishes with a real-table baseline: `tests/unit/process_supervision/test_windows_process.py:2666`. `_open_handle_count` invokes `gc.collect()` on every reading: `tests/unit/process_supervision/test_windows_process.py:539`. Obtain the historical failing assertion and its settle record. |
| `test_windows_process.py::test_terminate_tree_and_inspection_leave_the_handle_table_unchanged`, twice | **(c), unsupported attribution from aggregate handle equality; possible product leak remains UNVERIFIED.** Run 2 ended **199 handles below** its captured baseline. That demonstrates that the observed total changed; it neither identifies an operation-owned leak nor excludes one concealed by unrelated closures. | The baseline includes the live launch’s retained resources, then is reused after inspection and tree termination: `tests/unit/process_supervision/test_windows_process.py:1782`. The settle helper observes only the total: `tests/unit/process_supervision/test_windows_process.py:450`. Production closes temporary inspection and descendant handles in `finally` paths: `src/crypto_lab/process_supervision/windows_process.py:179`, `src/crypto_lab/process_supervision/windows_process.py:287`. Settle records must identify which checkpoint failed; acquisition/release accounting must identify any outstanding operation-owned resource. |
| `test_windows_process.py::test_an_open_process_failure_at_launch_is_an_open_process_launch_failure` | **(c) is the leading candidate if its final equality failed; (a) remains possible if abandonment left a child alive.** The historical message is missing, so classification of that occurrence is **UNVERIFIED**. | The test checks error mapping, descendant absence, then aggregate equality: `tests/unit/process_supervision/test_windows_process.py:1969`. Production abandons the suspended child after the injected open failure: `src/crypto_lab/process_supervision/windows_process.py:620`. Abandonment suppresses a bounded wait timeout: `src/crypto_lab/process_supervision/windows_process.py:524`. Capture the failing assertion, abandonment wait outcome, exact child identity, pipe closure and retained `Popen` lifetime. A surviving owned child requires a product correction. |
| `test_windows_process.py::test_a_launch_failure_leaves_no_child_and_no_extra_handle` | **(c), likely aggregate-count interference.** A missing executable exercises the `Popen` failure return, but the historical failing assertion is **UNVERIFIED**. | The test captures a global count around a missing-executable launch: `tests/unit/process_supervision/test_windows_process.py:1657`. Production maps the `Popen` exception directly to `LaunchFailure`: `src/crypto_lab/process_supervision/windows_process.py:588`, `src/crypto_lab/process_supervision/windows_process.py:600`. Observe the exact failing assertion and resources acquired during the failed launch, including standard-library resources. |
| `test_windows_process.py::test_terminating_an_already_exited_root_reports_no_failure` | **(b), an unmet natural-exit setup condition; underlying reason UNVERIFIED.** The failure happened before `terminate_tree`. `_exited` can demand absence even when its first wait returned `None`. If that happened, the observation is permitted by production. If the first wait returned `0`, the subsequent matching-live inspection needs product-level investigation. | The test launches `"pass"`, calls `_exited`, then invokes termination: `tests/unit/process_supervision/test_windows_process.py:949`. `_exited` records but does not require success from its first wait before asserting absence: `tests/unit/process_supervision/test_windows_process.py:433`. Its ledger already records the first return, elapsed time and presence: `tests/unit/process_supervision/test_windows_process.py:594`. That row is the first decisive observation. |
| `test_windows_process.py::test_cancel_read_unblocks_a_reader_whose_pipe_a_grandchild_still_holds` | **(b), failure to establish the fixture; startup stall or product launch defect remains UNVERIFIED.** The reader under test had not been constructed. The ten-second read covers a nested startup/readiness chain, rather than cancellation. | The spawner waits for its sleeper’s readiness before printing the PID: `tests/unit/process_supervision/test_windows_process.py:234`. `_pid_line` delegates to a daemon-thread read with one ten-second join: `tests/unit/process_supervision/test_windows_process.py:548`, `tests/unit/process_supervision/test_windows_process.py:569`. The failing PID read precedes `PipeReader` construction: `tests/unit/process_supervision/test_windows_process.py:983`. Record bounded startup phases, exact owned identities, root wait status, child failures and which readiness message was reached. |
| `test_windows_api.py::test_the_descendant_walk_of_this_process_is_empty_and_leaks_no_handle` | **(c) for the count assertion; (b) for the empty-tree setup assumption if a test-owned descendant survived.** Which failed is **UNVERIFIED**. | Both assertions occur together: `tests/unit/process_supervision/test_windows_api.py:368`. The count includes all pytest-process handles and invokes collection: `tests/unit/process_supervision/test_windows_api.py:146`. Production closes the snapshot and candidate process handles: `src/crypto_lab/process_supervision/windows_api.py:554`, `src/crypto_lab/process_supervision/windows_api.py:591`. Obtain the failing assertion and any returned identities. Do not dismiss a surviving owned child as handle-count noise. |
| `test_windows_api.py::test_a_failed_job_limit_closes_the_new_job_and_raises_with_its_number` | **(c), likely whole-process equality interference; actual occurrence UNVERIFIED.** The error-number and exact-job-closure obligations remain substantive. | The test injects failure, checks the captured error and compares total handles: `tests/unit/process_supervision/test_windows_api.py:519`. Production captures the error, closes the newly created job and re-raises: `src/crypto_lab/process_supervision/windows_api.py:421`. Record the exact created job, its successful close and the failing assertion. A missing close or wrong error number is a product defect. |
| `test_artifact_store.py::test_the_guard_literals_moved_to_the_task_four_sizes`, twice | **Deterministic test/guard maintenance mismatch, already identified as a real guard update.** It is not evidence for a timing diagnosis. | The assertions pin exact source/module/root/deferred-name inventories: `tests/unit/artifacts/test_artifact_store.py:2030`. Preserve the accepted updates. These files do not enter this correction’s write bound. |

### Additional production lead requiring investigation

`resume_initial_thread` warrants a targeted check before attributing Run 3 to scheduling:

1. `_first_thread_of` returns the first snapshot entry matching the PID: `src/crypto_lab/process_supervision/windows_api.py:500`.
2. `resume_initial_thread` resumes that thread and rejects only the failure sentinel; it accepts a previous suspend count of zero: `src/crypto_lab/process_supervision/windows_api.py:521`.
3. Its documented reasoning assumes the suspended new process has exactly one thread: `src/crypto_lab/process_supervision/windows_api.py:32`.

The supplied evidence does not establish whether that assumption held for either failed launch. **UNVERIFIED:** the selected thread, its relationship to the initial thread, and the resume result. Evidence that another thread was selected while the initial thread remained suspended would establish a product defect requiring correction. The presence of endpoint-security processes alone establishes none of this.

The jobless fixture also has an ownership gap worth closing: the tracker initially owns only the root, and the sleeper is adopted only after the PID read succeeds. See `tests/unit/process_supervision/test_windows_process.py:665` and `tests/unit/process_supervision/test_windows_process.py:983`. Failure before adoption must still have demonstrably complete cleanup.

## 2. SELECTION

Select **one Stage 7 corrective mission: diagnose and correct Windows launch-fixture synchronization and operation-owned resource verification**.

Place execution in **Workstream A**, which owns these product modules and tests. Workstream B’s idle 85 turns and zero deferrals do not transfer product-write ownership. An independently admitted read-only review can use its capacity, but its Project 2 worker mission must not receive these product paths implicitly.

Reserve an estimated **12–24 advisor turns**, with an early checkpoint after obtaining the missing evidence. This leaves approximately **131–143** of A’s current turns. That accommodates part of Stage 10’s estimate, but no longer preserves its conservative 155-turn reservation. Before Stage 10 dispatch, record a refreshed remaining-work estimate and sufficient authorized capacity. Do not assume a ceiling increase or borrow B’s balance.

The correction must:

- Replace whole-pytest-process equality as leak proof with **exact accounting for resources acquired, released or explicitly retained by the operation**. Unrelated handle closures must not conceal a leak; unrelated churn must not fail correct cleanup.
- Preserve real Windows execution, exact native errors, child absence, PID-plus-creation identity, job membership, cancellation and reader-end assertions.
- Establish and own the fixture tree before permitting an intermediate parent to exit. Use explicit bounded readiness/acknowledgement, with cleanup covering partial setup and failed reads.
- Distinguish failure to establish natural exit from behavior after an observed exit. A timed-out wait remains a failure; it must never become a passing “already exited” case.
- Fix production if the investigation demonstrates defective resume, abandonment, ownership or cleanup behavior.

It must **not** change launcher or verifier bytes, dependencies, coverage settings, Hypothesis settings, example domains/counts, production deadlines, existing skip permissions, schemas, migrations, Stage 10 implementation, or unrelated guards.

No longer bound is selected. No inspected product contract supplies the necessary completion guarantee. No arbitrary sleep, retry-until-green loop, skip, xfail, tolerance, or threshold reduction is authorized.

The hashing property remains unchanged and receives serial focused regression coverage. A new serial failure returns to diagnosis; it does not authorize extending the existing timing-insensitive decorator to another property.

## 3. OWNER-DELEGATED TECHNICAL DECISIONS

These are **model decisions under delegated authority**, not new owner rulings.

| Class | Summary and affected clauses | Chosen solution and preserved guarantees |
|---|---|---|
| `correction_ordering` | Corrective work precedes Stage 10 P0 completion and implementation dispatch. Affects Stage 10 plan §1.4 P0 and §9.1. | Preserve all three failed baselines. Perform a reviewed correction, then require its own complete PASSED verifier. No fourth unchanged baseline. |
| `implementation_interpretation` | Whole-process equality is an unreliable proxy for the resource promise. Affects the R2 commentary/oracle and structural callers at `tests/unit/process_supervision/test_windows_process.py:450`, `tests/unit/process_supervision/test_windows_process.py:2679`, and corresponding API tests. | Replace the proxy with exact operation-owned accounting and planted leak controls. Required unaccounted resources remain exactly zero. Record the R2 proof-method replacement explicitly; do not describe it as merely increasing settling time. |
| `implementation_interpretation` | Natural-exit and pipe-holder preconditions must precede the behavior assertion. Affects `tests/unit/process_supervision/test_windows_process.py:433` and `tests/unit/process_supervision/test_windows_process.py:975`. | Add explicit fixture synchronization and failure evidence. Preserve exact exit codes, fresh identity-safe absence, timeout failures and cancellation of an actually blocked reader. Do not reinterpret `ALIVE_MATCHING` as absence. |
| `task_sequencing` | Ownership and remaining capacity. | Execute under A’s product ownership; reforecast Stage 10 before dispatch. B’s balance supplies no implicit write authority or budget transfer. |

The seven permitted decision classes are recorded in the accepted Stage 10 plan at `docs/superpowers/plans/2026-08-10-project-1-cli-composition-end-to-end-acceptance-implementation-plan.md:437`. No owner-held scope, security, publication-destination, floor-file or budget exception is taken.

## 4. THE PLAN

### Task 1 - Diagnose and correct Windows process baseline failures

**Files modified.** `tests/unit/process_supervision/test_windows_process.py`, `tests/unit/process_supervision/test_windows_api.py`, `src/crypto_lab/process_supervision/windows_process.py`, `src/crypto_lab/process_supervision/windows_api.py`

Create no repository files. These four paths are the maximum worker bound. Production changes require a demonstrated defect and focused RED evidence; unchanged paths are excluded from the final commit manifest. Controller evidence and registration changes remain operator-owned, outside this worker bound.

**Subject and placement.**

Use Workstream A and a registered corrective branch descending from `bc05568d92155cebd58345d260d42ecf621a5d43`. Preserve the accepted Stage 10 plan and all three failed-verifier records. Freeze concurrent product work.

The correction is a Stage 7 prerequisite mission, not Stage 10 implementation. Record its budget separately because the Stage 10 estimate excludes corrective missions: `docs/superpowers/plans/2026-08-10-project-1-cli-composition-end-to-end-acceptance-implementation-plan.md:5110`.

**Step 1 — Establish the evidence and executable prerequisites.**

The operator must:

1. Confirm branch registration, accepted parent, ancestry, clean subject and exact worker bound.
2. Confirm managed CPython using `uv python find --managed-python --system --no-python-downloads 3.12`. The advisor’s cache-access failure is unresolved prerequisite evidence, not proof that Python is missing.
3. Confirm offline lock/synchronization prerequisites through the existing operator profiles. Acquire nothing.
4. Preserve complete failure records, reproduction examples and available `termination-shapes` evidence from all three runs.
5. Obtain the Run 3 natural-exit row: first wait return, elapsed time and inspected presence. Obtain assertion-level records for historical failures whose messages were not supplied.
6. Record the exact Run 2 settle checkpoint and available resource records.

Run focused work serially under the shared-host discipline. Do not run another unchanged complete baseline.

**Step 2 — Obtain focused RED and discriminate mechanisms.**

First execute the unchanged affected cases, preserving pass and failure results:

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/unit/process_supervision/test_windows_process.py::test_terminate_tree_and_inspection_leave_the_handle_table_unchanged tests/unit/process_supervision/test_windows_process.py::test_terminating_an_already_exited_root_reports_no_failure tests/unit/process_supervision/test_windows_process.py::test_cancel_read_unblocks_a_reader_whose_pipe_a_grandchild_still_holds tests/unit/process_supervision/test_windows_api.py::test_the_descendant_walk_of_this_process_is_empty_and_leaks_no_handle tests/unit/process_supervision/test_windows_api.py::test_a_failed_job_limit_closes_the_new_job_and_raises_with_its_number -q
```

A passing focused rerun does not establish a correction.

Add narrowly bounded observations through the existing test-local spy/proxy and evidence patterns:

- Account for real acquisitions, successful closes, ownership transfers and intentionally retained resources. Include snapshots, process/thread/job handles and launch-side resources; distinguish the deliberately retained `Popen` handle from temporary handles. Its intended lifetime is documented at `src/crypto_lab/process_supervision/windows_process.py:310`.
- Record the launch/readiness phase reached, first wait result and exact owned identities.
- Determine whether the selected resume thread satisfies the production assumption. Capture the resume result without repeatedly resuming arbitrary threads.
- Verify partial-setup cleanup, including a readiness reader that times out and a descendant not yet reported through the PID line.
- Do not inspect ambient environment values, credentials, unrelated process memory or command lines.

Author semantic regression controls with these proposed module-qualified selectors:

- `tests/unit/process_supervision/test_windows_process.py::test_an_operation_owned_leak_is_detected_despite_unrelated_handle_closure`
- `tests/unit/process_supervision/test_windows_process.py::test_unrelated_handle_churn_does_not_fail_balanced_operation_cleanup`
- `tests/unit/process_supervision/test_windows_process.py::test_a_natural_exit_timeout_never_establishes_the_already_exited_precondition`
- `tests/unit/process_supervision/test_windows_process.py::test_readiness_failure_cleans_the_partially_established_tree_and_reader`
- `tests/unit/process_supervision/test_windows_api.py::test_a_failed_job_limit_closes_the_exact_job_it_created`

Demonstrate that the old aggregate oracle can miss a planted owned leak when an unrelated handle closes, and can reject balanced ownership under unrelated churn. A missing helper/import alone is insufficient RED evidence. Planted resources must be safely reclaimed after the expected assertion.

For a demonstrated production defect, add a focused test that reproduces the actual faulty transition before changing production. Record its module-qualified selector and RED result. Do not invent a production fix from the unverified resume lead.

**Step 3 — Implement the minimum correction and focused GREEN.**

Implement exact resource accounting:

- Every temporary operation-owned acquisition must have its corresponding successful release.
- Every retained resource must have an explicit current owner and verified eventual release at the relevant lifetime boundary.
- Handle-number reuse must not be mistaken for continuous ownership; account for acquisition lifetimes.
- No missing close may be hidden by an unrelated close.
- Preserve descendant absence and failed-cleanup reporting independently of resource accounting.
- Exercise real APIs in positive cases. Fake counters alone do not prove real cleanup.

Replace the affected live aggregate-count assertions and update their structural pins together. Preserve deterministic exact-counter negative controls where they still test the settling helper; remove dependence on the real pytest handle table from those helper controls. Relevant pins are at `tests/unit/process_supervision/test_windows_process.py:2666` and `tests/unit/process_supervision/test_windows_process.py:2679`.

Correct fixture synchronization:

- Keep test-owned parent processes alive until required descendants have been identified and adopted by PID plus creation identity.
- Use explicit bounded readiness/acknowledgement and flushed phase messages.
- Preserve the original observation bounds; do not renew them indefinitely through progress messages.
- Ensure failed setup cancels/joins its readers and cleans every owned identity.
- Establish natural exit before testing an already-exited root. A timeout fails with its observed facts.
- Preserve the pipe-holder test’s substantive sequence: root exited with exact code; another live owned process holds the write end; reader is blocked; cancellation succeeds; reader ends as `CANCELLED`; resources close.

The existing reader contract distinguishes cancelled I/O from EOF at `src/crypto_lab/process_supervision/readers.py:91`. Preserve that distinction.

If the evidence establishes a product defect, fix that defect within the declared production bound. If the repair requires another path, a changed launch contract, a floor file or another authority exception, stop that dependent work and obtain a revised exact corrective plan. Do not broaden the worker manifest.

Run the new controls RED, then GREEN:

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/unit/process_supervision/test_windows_process.py::test_an_operation_owned_leak_is_detected_despite_unrelated_handle_closure tests/unit/process_supervision/test_windows_process.py::test_unrelated_handle_churn_does_not_fail_balanced_operation_cleanup tests/unit/process_supervision/test_windows_process.py::test_a_natural_exit_timeout_never_establishes_the_already_exited_precondition tests/unit/process_supervision/test_windows_process.py::test_readiness_failure_cleans_the_partially_established_tree_and_reader tests/unit/process_supervision/test_windows_api.py::test_a_failed_job_limit_closes_the_exact_job_it_created -q
```

Run any actual product-defect selector through the same profile, followed by the original affected selectors. Record why the correction addresses the observed mechanism. An improved error message or diagnostic record alone does not close a failing behavior.

**Step 4 — Run bounded regression and worker quality checks.**

Run the complete affected modules, supervision integration, contract and boundary regressions serially:

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/unit/process_supervision tests/integration/process_supervision tests/contract tests/property/test_strategy_hashing.py tests/safety tests/architecture tests/unit/test_package_layout.py -q
```

The strategy property remains unchanged, including its timing settings, generated domain and independent loads. A serial recurrence requires diagnosis before acceptance.

Then run:

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-format-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-check-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 mypy-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 schema-generate-check
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 migration-check
```

Apply formatting corrections only within the bound. Report unrelated failures; do not repair them silently. Focused runs with cleared addopts provide no acceptance-coverage evidence.

**Step 5 — Freeze, independently review and fully verify.**

Freeze the candidate with its parent, exact changed-file manifest and subject digest.

Independent review must assess:

- Every recorded failure’s disposition, including unresolved alternatives.
- Whether a real product defect was fixed wherever demonstrated.
- Whether replacement assertions prove the same resource, identity and cancellation guarantees.
- Leak detection under cancelling unrelated churn.
- Partial setup, reader timeout and descendant cleanup.
- Preservation of production bounds, coverage, Hypothesis settings and skip permissions.
- Exact source, reference and diff inspection; GitNexus remains disabled.

Do not accept an unexplained Run 3 failure merely because another execution passes.

After review corrections, the operator runs the unchanged complete verifier through the controller’s admitted serial-verifier route, with readiness checks, execution-identity checks and the shared host lock:

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/verify.ps1
```

Require all eleven verifier steps to pass. Preserve warnings, skip counts and attribution limits, coverage data, elapsed time and every failure or later `NOT_RUN` step.

Keep the configured 90-percent floor and measurement settings unchanged. Preserve the three failed runs’ reported 98.67-percent measurements and any available unrounded data; do not silently lower the historical coverage requirement. Record the corrected subject’s actual measured coverage without rounding down.

Require journalled independent **APPROVE** and accepted **PASSED** full verification covering identical subject bytes. Follow the controller’s formal review ordering if its acceptance route requires a post-verifier review.

If verification fails or is interrupted, preserve its evidence and diagnose the actual failure. Do not enter an unchanged-baseline retry loop.

**Step 6 — Commit, publish and release the prerequisite.**

The controller must:

1. Confirm that the final diff and staged paths exactly match the accepted manifest, with no floor or unrelated file.
2. Commit on the accepted parent using a truthful subject, such as `test: correct windows process fixture and resource proofs`, or `fix:` when production behavior was corrected.
3. Verify that the committed tree matches the reviewed and fully verified subject and descends from `bc05568d92155cebd58345d260d42ecf621a5d43`.
4. Publish the exact commit through the existing authorized controller route to the registered corrective branch, without force, and verify the remote ref.
5. Retain verification/review/publication receipts in controller-owned evidence; do not alter the frozen product tree to insert future receipts.
6. Record the corrected commit as Stage 10’s prerequisite subject and make the implementation branch descend from it. Any combined subject with other changes requires its own applicable verification.

No new publication destination, main publication or policy-floor exception is authorized.

**The corrected subject’s own PASSED complete verification is the fresh passing baseline required by the owner. Stage 10 implementation dispatch waits for that baseline, independent approval, exact commit, verified branch publication and sufficient recorded remaining capacity.** It is not Stage 10 or Project 1 application acceptance.

**Completion token.**

Emit `WINDOWS_PROCESS_BASELINE_CORRECTION_COMPLETE` only after all gates above are satisfied, accompanied by the exact commit, branch, manifest, review ID, full-verifier ID, coverage/skip/warning record and verified remote ref.

Until then, report the last proved state and outstanding gate. This plan emits no completion claim.

## 5. DISPATCH READINESS CHECKLIST

- [ ] Preserve all three failed baselines; prohibit a fourth unchanged baseline.
- [ ] Register the corrective mission under Workstream A with the four-path maximum bound and a branch descending from `bc05568d92155cebd58345d260d42ecf621a5d43`.
- [ ] Resolve managed-Python discovery/cache access and confirm offline prerequisites without acquisition.
- [ ] Make the historical transcripts, Hypothesis example and termination-shape records available to the worker.
- [ ] Record the model decisions explicitly, including the R2 proof-method replacement.
- [ ] Admit only the six worker-callable profiles; keep floor files outside the bound.
- [ ] Reserve corrective turns and reforecast Stage 10 capacity; assume no budget transfer or increase.
- [ ] Schedule focused work, independent review and full verification without overlapping heavy execution.
- [ ] Verify the registered non-force publication route before dispatch.
- [ ] Keep Stage 10 implementation blocked until the corrected subject has its own accepted PASSED full baseline and the remaining release gates are recorded.

The corrective mission is ready for operator provisioning. Its runtime diagnosis, implementation and acceptance remain **UNVERIFIED**.
