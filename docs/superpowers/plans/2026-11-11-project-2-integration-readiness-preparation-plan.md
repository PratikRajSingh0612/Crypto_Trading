# Project 2 integration-readiness preparation — bounded plan

**Status.** Revision 3 (revision 1 plus the independent review's five MINOR findings and its revision-2 citation MINOR folded), proposed under STANDING OWNER AUTHORIZATION 2026-11-10, AUTONOMOUS PROGRAMME DELIVERY (revision 1 was extracted verbatim from the advisor's selection of 2026-11-11 05:06Z with the two sentences that described Stage 9 publication as pending replaced, because the owner published main at 05:03Z while that turn ran). Requires independent plan APPROVE and advisor DELEGATED_PLAN_ACCEPTED against the exact committed plan. This document records no runtime acceptance.

**Plan location.** `docs/superpowers/plans/2026-11-11-project-2-integration-readiness-preparation-plan.md`.

**Branch and base.** New branch and worktree `project-2-integration-readiness`, descending from published slice-4 commit `19d4db1e77ae8053a9f3b7feecac78b9cb81f887`, above plan `9e07ce23` and published slice-3 commit `970c1fb5`. The controller commits this plan separately; that plan commit becomes the implementation gate’s base_commit. Completed missions remain closed.

**Readiness.** NOT_READY until exact plan acceptance, policy registration, both offline environments, execution binding and resource readiness are recorded. Stage 9 is integrated: origin/main is 874fb51b since 2026-11-11 05:03Z. This preparation does not combine trees; the subsequent combined integration still needs its own reviewed route and fresh acceptance evidence.

## 1. Authority, sources and consumed versions

Unprefixed paths identify the product repository. CTL means `Crypto_Lab_Dev_Controller-dev`; P2CTL means `Crypto_Lab_Dev_Controller_P2`. Product references identify the P2 tree at `19d4db1e`, except explicitly identified Stage 9 references at `874fb51b`.

Sources:

- `P2CTL/config/mission_checkpoint.md:232-314`: programme authority, priorities, readiness, ownership, resource limits and integration responsibility.
- `CTL/docs/programme-index.md:66-94`: Stage 9 publication boundary, published P2 slices and outstanding obligations.
- `docs/superpowers/plans/2026-11-11-project-2-offline-data-review-corrections-plan.md:29-40`: consumed contracts and requirement for a separately reviewed combined integration route.
- `offline_data/pyproject.toml:11-13`, `:52-53`: core dependency through the non-editable parent path; `:81-100`: existing branch-coverage floor.
- `offline_data/tests/integration/test_sqlite_dataset_registration.py:3-23`, `:251-285`: temporary registration, migration, reopen and read-back contract.
- `offline_data/README.md:376`: retained refusal-table follow-up; `:724-749`: interim format, temporary-registration restriction and pending finalization.
- Stage 9 `src/crypto_lab/persistence/migrations/versions/r0002_stage9_artifacts.py:1-22`, `:32-33`: migration increment over the Stage 8 baseline.
- `P2CTL/src/clabctl/gitops.py:540-549`: main-acceptance and checked-out-branch publication requirements.
- `offline_data/scripts/invoke-offline-uv.ps1:21-33`, `:168-254`: closed offline profiles (bootstrap profiles at :168-198; ruff-format-all, ruff-check-all and mypy-all at :222-254).
- `offline_data/scripts/verify-offline.ps1:21-49`: unchanged sub-project acceptance script.

Consumed versions remain:

| Contract | Version or source |
|---|---|
| Core used by this task’s executable checks | `079395bec70f1deda406d0ca14b2d4bf79aaf063`, preserved in the P2 branch |
| Stage 9 comparison snapshot | `874fb51b4959ca6c3b8e5a2bc640b9af99b176f1` |
| Dataset descriptor and partition schemas | `1.0.0` |
| Metadata hash profile | `dataset-metadata/v1` |
| Input formats | `ohlcv-csv/1`, `binance-spot-kline-csv/1` |
| Provenance source versions | Existing `1.0.0` values |
| Output and column schema | `normalized-ndjson/0.1.0`, `0.1.0` |
| Sub-project distribution | `crypto-lab-offline-data` `0.1.0` |

Do not import Stage 9 into the task branch if main advances. Record any newer target as requiring renewed integration preparation.

## 2. Required brief

Produce a source-grounded readiness brief containing:

1. **Preserved delivery inventory.** Record full commit identities and ancestry for slice 1 `3a47d4c9`, slice 2 `4d70f673`, slice 3 `970c1fb5` and slice 4 `19d4db1e`. Confirm whether the latest stack contains every earlier delivery. Distinguish published work from the preserved, unpublished mission-3 alternative `refs/tags/preserved/p2-sqlite-registration-contract-mission3` (`ae529fd79b0b158b4a604517f8d529a9533cd987`, not an ancestor of `19d4db1e`; its test module and README equal the published slice 3); do not propose replaying both.

2. **Change and contract inventory.** Compare both branches with common baseline `079395be`. List actual overlapping paths, consumed interfaces and relevant Stage 9 persistence changes. Record unchanged contracts only where the inspected source or diff proves that claim. Separate textual compatibility from runtime compatibility.

3. **Environment binding.** Explain how the non-editable parent dependency must consume the eventual combined core. Specify the evidence a later route must retain to prevent testing a stale Stage 8 installation. Preserve separate core and sub-project environments; identify any unresolved execution capability rather than inventing a command.

4. **Combined-tree acceptance requirements.** Identify the existing metadata round-trip, temporary SQLite registration, normalization, reader, CLI and safety suites that must run against the eventual combined tree. Require both complete verifiers, all existing floors, schema/migration checks, build and distribution checks, hygiene, and independent review. Specify binding to the exact combined subject and execution environments.

5. **Controller integration gaps and handoff.** Inventory existing controller capabilities and missing transitions for combining branches, verifying the combined tree, recording milestone acceptance and publishing the checked-out destination. Distinguish implementation gaps from owner-held permissions. Provide an ordered requirements checklist for a later reviewed integration route; do not present it as an executable route already available.

6. **Explicit residuals.** Preserve P2-B1, P2-B2 and P2-B3; pending dataset finalization; core ownership of shared validation; and the README line-376 follow-up. Identify its omitted residual-carriage-return case without editing the README.

Every material conclusion must cite repository-relative path:line evidence or an exact read-only Git command and its observed result. Record inspected repository commits. Use repository/worktree names instead of machine-local paths.

The brief must state that this task neither creates nor tests a combined tree. Its full gate validates the documentation subject on the preserved P2 core baseline.

## 3. Task decomposition

### Task 1 - Prepare the Project 2 combined-integration readiness brief

**Objective.** Deliver section 2 as the concrete handoff for finishing the preserved P2 stack’s later integration.

**Prerequisites.** Independent plan APPROVE and advisor DELEGATED_PLAN_ACCEPTED bound to the exact plan bytes and commit; gate based on that plan commit; registered branch, worktree and publication refspec; unique mission identity; both environments synchronized offline; admitted execution profiles; resource and accounting preflight passed.

**Files created.** `offline_data/docs/2026-11-11-integration-readiness.md` (UTF-8 without BOM, LF line endings, no trailing whitespace).

**Files modified.** None.

**Writable boundary.** The single created file is the complete worker manifest. The controller commits the plan separately before dispatch; it is not worker-writable. No directory bounds or patterns.

**Exclusions.** No production-code, test, fixture, golden, README, shared-contract, schema, migration, lock, dependency, launcher, verifier or controller change. No branch combination, rebase, reset, main publication or milestone-acceptance note. No acquisition, network/source access, real-data download, engine execution, persistent registration or artifact finalization.

**Execution.** Work from the registered worktree root. Inspect source through Read/Glob/Grep and the existing admitted read-only Git verbs: status, diff, log, show and rev-parse (blob identities via `git rev-parse <commit>:<path>`; `hash-object` and `diff --raw` are not admitted). Inspect Stage 9 through existing committed objects; stop if a required object is unavailable. Read the two controller trees read-only, cited by the CTL/P2CTL prefix; if they are not readable, derive section 2 item 5 from section 1's cited ranges and mark it for controller-side confirmation. Do not fetch or widen tool permissions.

Write the brief, then run each command separately through the worker’s Bash tool:

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/invoke-offline-uv.ps1 ruff-format-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/invoke-offline-uv.ps1 ruff-check-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/invoke-offline-uv.ps1 mypy-all
```

These profiles check the preserved executable baseline; independent review validates the brief’s technical conclusions. No new tests or artificial RED/GREEN exercise is required for this analytical document. Do not invoke uv, Python or installed tools directly.

- [ ] Establish the published ancestry and inspected source identities.
- [ ] Inventory actual change overlap, contracts, migration impact and environment binding.
- [ ] Define the later combined-tree evidence requirements and controller gaps.
- [ ] Record residuals, owner-held boundaries and source citations.
- [ ] Pass the three quality profiles and leave exactly the authorized brief changed.
- [ ] Complete section 4 through the controller.

**Commit message.** `docs(offline-data): record Project 2 integration readiness`

## 4. Verification, review, publication and completion

The controller issues VERIFY with verification_scope=full and verification_targets=[].

Run the unchanged scripts in this order:

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./offline_data/scripts/verify-offline.ps1
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/verify.ps1
```

Both must be PASSED for the same final subject and recorded environments. Preserve the P2 98.61 percent branch-coverage floor and every configured core gate. Report all warnings, skips and failures. Previous slice passes and A’s merged-main pass do not cover this subject.

**Model scheduling decision — task_sequencing.** This preparation uses B’s free slot while A is parked. Before B’s full gate, the operator records that A has no active or pending verifier reservation. If A resumes before that gate starts, A takes priority. Finish an active verifier before starting another. All heavy verification remains serial under `.crypto-lab-host/verifier.lock`; retain dispatch_wait_markers=[verify.ps1]. Change no scheduler, limits or counters.

After full PASSED verification, obtain one independent implementation review APPROVE on the exact final subject, with the worker idle and no concurrent tests/verifier. The reviewer checks ancestry, source citations, contract and environment reasoning, the distinction between existing and missing controller capabilities, complete integration-gate requirements, owner boundaries and the exact one-file diff.

Resolve findings within bounds. A changed subject requires renewed verification and review.

Then:

1. Advisor issues ACCEPT_TASK against PASSED verification and APPROVE review.
2. Controller commits exactly the accepted one-file manifest.
3. Controller scans the complete outgoing range, including separate plan commits, for publication safety.
4. Controller publishes non-force to `origin/project-2-integration-readiness` through its registered single-branch refspec and confirms the remote commit.
5. Record verification, review, acceptance, commit and publication identities.

Record completion token P2_INTEGRATION_READINESS_PLAN_COMPLETE only after successful acceptance, commit and publication.

Completion accepts the preparation deliverable. Actual combined integration, main publication, P2 finalization and application acceptance remain pending.
