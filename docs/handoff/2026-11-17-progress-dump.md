# Crypto Trading Lab: progress dump at handoff (2026-11-17)

This is the state of the programme on 2026-11-17, written by the Claude Code controller session
when the owner moved development to a different AI tool on another system. It supersedes the
"current state" sections of the owner's Antigravity package in `local dump/` (committed as-is
beside this file's commit), which were assembled from the public snapshot of `main` at
`874fb51b` and do not know the later work below. Everything here is reproducible from Git: SHAs
are given for every claim, and anything not verified is said to be unverified.

## 1. Where everything lives

| What | Where | Notes |
|---|---|---|
| Product code (this repository, PUBLIC) | `main` | Everything below is merged into `main` as of this dump |
| Stage 10 work branch | `project-1-stage-10-implementation` @ `4080b6b` | Published; merged into `main` |
| Stage 10 P0 correction branch | `project-1-stage-10-p0-correction` @ `3e5af186` | Published; contained in the Stage 10 branch |
| Project 2 stack | `project-2-installed-core-identity` @ `662ae4df` | Published; merged into `main` by `6678c15` |
| Project 3 branch | `project-3-vectorbt-adapter` @ `853e6a0` | Published; merged into `main` |
| Controller (the relay that ran advisor, worker and verifier) | private repository `Crypto_Lab_Dev_Controller`, branches `master` (root A: Project 1) and `p2-root` (second root: Projects 2 and 3) | Holds the decision records (`config/records/`), the mission checkpoints, the controller code and a detailed private dump at `docs/handoff/` |
| Owner's Antigravity handoff package | `local dump/` in this repository | Committed byte-for-byte at the owner's instruction; excluded from ruff |
| NOT in Git (local machine only) | controller journals and evidence (`state/`, `evidence/` in each controller root), the operator file `config/controller.config.json` (no secrets), every `.venv`, the uv cache | Copy by hand if the provenance trail is needed on the new system |

Older local-only stage and plan branches (`project-1-stage-1-foundation` ... `project-1-stage-9-plan`,
`project-2-offline-data-plan`, `integration-p2-stack-main`) are fully contained in `main`; nothing in them is lost.

## 2. Programme status

| Project | Scope | Status at handoff |
|---|---|---|
| P1 Engine-neutral core | Stages 1-10 | Stages 1-9 complete and on `main`. Stage 10 in progress: P0 correction, S10-T1 and S10-T2 done (see 3); S10-T3..S10-T8 remain |
| P2 Historical data ingestion | `offline_data/` sub-project, slice 1 | Slice 1 complete (missions 1-7) and on `main` (merge `6678c15`); limitations in 4 |
| P3 VectorBT Community adapter | `vectorbt_adapter/` sub-project | Isolated environment bootstrapped (VectorBT 1.2.0); slice plan revision 1 under review; no engine slice implemented (see 5) |
| P4-P13 | Freqtrade, NautilusTrader, Jesse, OctoBot, Hummingbot, LEAN, risk/wallet, Indian tax/TDS, dashboard, local LLM | Not started; briefs in `local dump/.../projects/` |

## 3. Project 1, Stage 10 (CLI composition and end-to-end acceptance)

- Plan: `docs/superpowers/plans/2026-08-10-project-1-cli-composition-end-to-end-acceptance-implementation-plan.md`,
  revision 4, commit `bc05568d`, sha256 `8496d165...`; eight serial tasks S10-T1..S10-T8, seven acceptance conditions.
- P0 baseline: the unchanged base failed three complete verifications on Windows process timing; the accepted correction
  `3e5af186` (tests only: `tests/unit/process_supervision/test_windows_process.py`, `test_windows_api.py`; whole-process
  handle counts replaced by operation-owned accounting) passed the full gate: 10566 passed, 2 skipped, coverage 98.67%.
- S10-T1 `ba4412a` (runtime services, application ports, Stage 10 guard foundation; 16 paths): ACCEPTED and published.
  Four worker rounds, including a real fix for a cancellation re-entry deadlock in the signal-handler bridge (in-progress
  guard set before any token call). Final full gate: 10597 passed, 2 skipped, 98.66% displayed; review APPROVE.
- S10-T2 `4080b6b` (startup integrity, reconciliation ordering, scheduling barrier; 18 paths): full gate PASSED
  (10643 passed, 2 skipped, 98.55% displayed) and independent review APPROVE on exactly these bytes; NOT accepted by the
  advisor because the owner paused all work before that step. An earlier full run failed once on
  `tests/integration/process_supervision/test_supervised_contract_matrix.py` row 25 (`heartbeat-timeout-run`,
  PROCESS_MISSING_HEARTBEAT absent); the same function passed 59/59 when run alone.
- Next: S10-T3 (explicit input registration, queue freeze, application audit wiring), then T4, T5; the plan's P1 operator
  step (the `cli-local` launcher amendment, one reviewed commit) must close before T6; T8 is documentation, acceptance
  evidence and the integration into `main`.
- Open items carried to Stage 10's final gate (none waived): the unrounded coverage comparison against the 98.67%
  baseline (runs show 98.55-98.67%; the displayed value moves by about 0.01 between unchanged runs); three timing
  observations from the P0 runs (hashing slow-generation health check; Run 3 natural-exit and process-id-line timeouts);
  the row 25 heartbeat-timeout intermittency; the owner-held corrective gates B1, B2 and conditional B3 from the plan.
- Capacity under the old controller: 233 of 356 advisor turns used; the advisor estimated 90-136 turns for T1-T8 at the
  start of Stage 10.

## 4. Project 2 (offline historical candle data, slice 1)

- `offline_data/` is an isolated sub-project with its own `pyproject.toml`, `uv.lock`, closed launcher
  `offline_data/scripts/invoke-offline-uv.ps1` and gate `offline_data/scripts/verify-offline.ps1`; it consumes the core
  as a non-editable installed package.
- Integration into `main`: merge `6678c159` (parents `874fb51b`, `662ae4df`, disjoint paths, no conflict resolution).
  In the integration worktree the full gate PASSED (offline 1264 passed, 100.00%; core 10528 passed, 2 skipped, 98.66%;
  the installed core reported migration head `r0002_stage9_artifacts`), independent review APPROVE, advisor ACCEPTED with
  no conditions. The route's second verification in the main checkout FAILED on two core tests that `main` then still
  carried, the old Windows handle-count tests that the Stage 10 correction replaces; the route therefore did not publish.
  `main` was pushed to `6678c15` on 2026-11-17 outside the route. With the Stage 10 merge, `main` now contains the
  corrected tests.
- Limitations (unchanged): the interim `normalized-ndjson/0.1.0` container is not registered as production data; Parquet
  (pyarrow) acquisition is not authorized; no real-source (network) validation; the artifact-finalizer obligation
  (Project 2 obligation 2) is open.

## 5. Project 3 (VectorBT Community adapter)

- Owner authorization (2026-11-15): VectorBT 1.2.0 Community, no extras, may be installed and imported only in the
  isolated `vectorbt_adapter/` environment while Project 1 is under development; recorded as a scoped bullet in
  `AGENTS.md`. Licence: Apache 2.0 with Commons Clause (internal research use; no paid service built on it).
- Bootstrap (done): `vectorbt_adapter/pyproject.toml` (virtual project, `vectorbt==1.2.0`, dev tools pinned to the same
  versions as offline_data), `vectorbt_adapter/uv.lock` (sha256 `7afac95b...`, 76 packages, all wheels with sha256 hashes
  from PyPI, win32/AMD64 only), and the closed launcher `vectorbt_adapter/scripts/invoke-vectorbt-uv.ps1` (derived from
  the offline_data launcher; `--no-build` on every lock and sync; two operator-only acquire profiles). The environment
  is local only: recreate it with `invoke-vectorbt-uv.ps1 sync` (offline after a one-time `sync-acquire`).
- Plan revision 1: `docs/superpowers/plans/2026-11-15-project-3-vectorbt-first-engine-slice-plan.md` (advisor-authored):
  one task P3-T1, an in-memory `sma_cross_long` simulation callable run against the real installed engine on the
  core's frozen synthetic close series, Cases A/B/C checked against an independent Decimal oracle, every
  `Portfolio.from_signals` argument explicit. Independent review: REQUEST_CHANGES. Blocking for the old controller only:
  its verifier's execution-surface file limit (20,000) is below the ~25.9k files of the core, base and engine
  environments. Important: the worker should not author the gate script and tool configuration that verify its own work;
  record a baseline digest of the engine environment before work and re-check it before acceptance. Minor: use
  `vectorbt.portfolio.nb`, pin accessor arguments, `git add -N` before whitespace checks.
- Not done: no engine execution code or test exists yet. An import is not an adapter test or integrated backtesting.

## 6. What `main` contains now, and how much of it was verified together

- Merge commits on top of `6678c15`: `c8ea258` (Stage 10 progress), `be761bd` (Project 3), then this dump's commit
  (`local dump/`, this file, and a ruff `extend-exclude` entry for `local dump` in the root `pyproject.toml`, because the
  package's `tools/collect_local_context.py` does not meet the repository's ruff rules and is kept byte-for-byte).
- Checks run on the merged tree before pushing: `ruff-check-all` and `ruff-format-all` pass (407 files), the core
  `lock-check` passes, and the core safety suite plus the package-layout test were run (result in the commit message of
  this dump). The complete gate (`scripts/verify.ps1` plus `offline_data/scripts/verify-offline.ps1`) was NOT run on the
  combined tree as a whole: each part's own full-gate evidence is listed in sections 3-5. Run it first on the new system.

## 7. How the work was run (useful when adopting the new tool)

- Roles: an advisor (Codex CLI, `gpt-6.1-sol`, read-only, enforced by the CLI's read-only permission profile) chose tasks,
  wrote and accepted plans and requested changes; a worker (Claude Code, Opus 5.5) implemented one plan task at a time
  within an exact path bound, test-first; independent read-only reviewers approved exact byte digests; a controller
  enforced plan gates, the worker's launcher allowlist, a serial complete verifier under a host lock with a
  competing-process scan, the commit of exactly the accepted manifest and non-force publication.
- Product rules that stay in force (see `AGENTS.md`): user-local uv-managed CPython 3.12 only; all execution through
  `scripts/invoke-uv.ps1` closed profiles; ordinary work offline; TDD; `scripts/verify.ps1` before claiming completion;
  no live trading, credentials, exchange or network clients; `Decimal` for money, UTC-aware timestamps; unknown fields
  rejected at boundaries; no real engine in Project 1.
- Practical pitfalls seen on this Windows host: Windows process-supervision tests are timing-sensitive under host load
  (keep the full gate alone on the machine); `ruff check .` covers every `.py` under the repository root; files written
  by some tools gain CRLF line endings; the core gate takes 45-60 minutes.

## 8. Open decisions at handoff

1. Project 1: owner rulings on corrective gates B1/B2/B3 and the three timing observations; the Stage 10 final coverage
   comparison.
2. Project 3: plan revision 2 (fold the review), then P3-T1. The old controller's file-limit blocker disappears if the
   new system verifies differently, but the engine environment must still be identity-checked before and after work.
3. Project 2: Parquet acquisition, real-source validation and finalizer integration remain owner-held.

## 9. Suggested first steps on the new system

1. Clone this repository; install uv and the user-local uv-managed CPython 3.12 (`uv python find --managed-python
   --system --no-python-downloads 3.12` must succeed); run `scripts/invoke-uv.ps1 lock-check` and `sync`, and the same
   for `offline_data/scripts/invoke-offline-uv.ps1`.
2. Run `offline_data/scripts/verify-offline.ps1` and `scripts/verify.ps1` on `main` to establish a fresh baseline for the
   combined tree before any new work.
3. Read `AGENTS.md`, the Stage 10 plan, and the decision records in the private controller repository
   (`config/records/` on `master` and `p2-root`), then continue with S10-T3.
