# COST-AWARE MODEL ROUTING — ADD GEMINI 3.8 FLASH

Revision 2, 2026-11-18. Supersedes revision 1 (commit `efec43c`, the owner's
text verbatim). Every revision 1 rule is kept; where revision 2 narrows or
interprets the owner's wording it says so in place. Revision 2 adds: a tier
map; classification recomputed from the diff; high-blast-radius and
owner-only classes; mechanical checks before review; reviewer strength and one commit bound
through focused checks, review and verifier; verifier quiet-window, acceptance
and flake rules; dispatch only on accepted prerequisites; named references;
placement; and an appendix of starting classes. Three independent read-only
reviews were folded in before publication.

Update the existing Gemini-only agent workflow.
Replace conflicting earlier model assignments rather than appending another
inconsistent policy.

Placement. Antigravity does not load this file from `docs/handoff/`. To make
it always-on, copy it into `.agents/rules/` with the same
`trigger: always_on` frontmatter as the existing rule files once that
directory reaches `main`. On 2026-11-18 those rule files hold no model or tier
assignment that this policy must replace; their only model statement ("Google
models through supported Antigravity routes only") is compatible. An
assignment held in Antigravity's own settings must be replaced there.

OBJECTIVE

Minimize total cost per accepted task while preserving correctness.
Do not optimize token price by accepting incomplete implementations,
weak tests or repeated failed attempts.

In this repository the dominant cost is rework, not tokens. The complete
verifier is `scripts/verify.ps1`, plus `offline_data/scripts/verify-offline.ps1`
when a change reaches `offline_data/` or integrates a combined tree. The core
gate alone takes 45-60 minutes of exclusive host time
(`docs/handoff/2026-11-17-progress-dump.md`, section 7). The cheapest controls
are the mechanical checks in section 3 and the plan task's focused
verification, both run before the complete verifier.

1. ROUTING

Routing is by capability tier. Section 2 maps tiers to model names; a model
name used anywhere else in this policy means that model's tier.

- Tier L (low cost): Gemini 3.8 Flash.
- Tier M (mid): Gemini 4 Hydrogen.
- Tier H (high): Gemini 4 Carbon; Gemini 4 Argon if Carbon is unavailable.

Use these defaults where the actual API/tool supports them:

A. Routine coordination, checkpoint summaries, file discovery and task packets:
   Tier L, Medium.

B. Documentation, bounded log summaries and mechanical non-behavioral edits:
   Tier L, Low or Medium. Not for pinned prose or any other section 3 class.

C. Small, well-defined, low-risk code changes and focused tests:
   Tier L, High, only when the change has no section 3 class.

D. Ordinary multi-file implementation and nontrivial debugging:
   Tier M, High.

E. Architecture, ambiguous contracts and critical implementation:
   Tier H, High.

F. Independent review. The first review runs in a fresh read-only context,
   never the implementing session, by a reviewer at least as strong as the
   strongest implementer of the change:
   - Ordinary substantive code, including Tier L code work and
     high-blast-radius work: Tier M, High.
   - Critical code: Tier H, High, for the critical files; the rest of the
     change follows the line above.
   - Owner-only changes (section 3): Tier H, High.
   - Documentation-only changes with no pinned prose and no other section 3
     class: Tier L in a separate review context.
   The reviewer reads the diff and the stored logs itself, at the recorded
   commit, and receives the outputs of the section 3 mechanical checks. A
   coordinator-written summary is not review input. A re-review of a
   correction may continue in the same reviewer context, given the change
   since that review and the re-run section 3 check outputs; it re-reviews the
   correction and the behavior it affects, read-only.

G. Verification:
   Actual commands establish results.
   Tier L may prepare an already-approved invocation and summarize its output.
   Do not spend premium-model calls continuously watching a running command.
   Acceptance and flake handling are in section 7.

The routine Tier L coordinator may dispatch clearly classified work within
the accepted plan. It must not independently weaken contracts, decide an
architectural ambiguity or treat its summary as acceptance evidence.
It may raise a task's class and never lowers one.

2. CHECK REAL MODEL SELECTION

Tier map. The names are owner-supplied and could not be confirmed from this
repository on 2026-11-18. Confirm each in the Antigravity selection controls
and record the actual name.

| Tier | Preferred | If unavailable |
|---|---|---|
| L | Gemini 3.8 Flash | Tier M (an upward move) |
| M | Gemini 4 Hydrogen | Tier H (an upward move) |
| H | Gemini 4 Carbon | Gemini 4 Argon; otherwise stop and report to the owner |

Verify models against the configured Gemini API and supported Antigravity
selection controls.

The documented Flash API identifier is gemini-3.8-flash.
Do not invent effort-suffixed API IDs or unsupported agent configuration.

A model name written in a prompt does not change the executing model.
Record the actual selected model and reasoning setting.

Keep the existing authentication and billing project.
Never print or copy the API key. As `AGENTS.md` requires, never inspect,
print, persist or log environment-variable values or credential-store
contents. Verify a model from the selection controls and the response's model
metadata, never from the key.

If a preferred model is unavailable, report the actual substitution.
Do not silently switch providers or authentication.
A substitution never moves work to a lower tier.

3. CLASSIFY BY RISK, NOT FILE COUNT

Do not assign Flash critical behavior merely because the patch is short.

A change has a section 3 class when any part of it is critical, owner-only or
high blast radius.

Who classifies:
- Before dispatch, the plan task records the class; where it is silent, the
  owner or a Tier H model does. A task with no recorded class is not
  dispatched.
- Before review, the class is recomputed by command: apply the path lists
  below to `git diff --name-only <base> <commit>`. Any hit raises the class.
  Work done below the raised tier is redone, or adopted and re-derived by a
  worker of that tier, and then reviewed at that tier.
- A test file takes the class of the source it exercises. A test file changed
  only in census or pin lines is high blast radius.
- The coordinator may raise a class and never lowers one.

Critical: Tier H implementation and Tier H review. Use Carbon/Argon directly
for:
- scheduler claims and concurrency;
- SQLite transactions, migrations and recovery;
- process ownership and cancellation;
- security and permission boundaries;
- authoritative audit/provenance behavior;
- financial semantics where an incorrect assumption changes results.

Critical paths (under `src/crypto_lab/` unless noted):
- `experiments/` (every module: the retry loop, compare-and-swap calls, queue
  freeze, scheduling, finalization and the `UnitOfWork` port)
- `process_supervision/` and `cli/` (dispatch mutex, cancellation bridge,
  startup reconciliation and scheduling permit, execution, input confinement)
- `persistence/` (including migrations), `audit/` and `artifacts/`
- `domain/experiment.py`, `domain/lifecycle.py`, `domain/retry.py` (queue
  freeze and lifecycle rules)
- `domain/hashing.py`, `domain/canonical_json.py`, `datasets/hashing.py`
  (identity and provenance)
- `domain/financial.py`, `domain/metrics.py`, `domain/records.py`,
  `strategy/evaluation.py` (Decimal results)
- `adapters/sanitization.py`, `adapters/paths.py` (adapter trust boundary)
- `schema_registry.py` and the published schemas in the root `schemas/`
  (extending a published schema needs an owner-approved correction)

An allowlist entry that admits network, subprocess, environment, filesystem
or engine access is critical wherever it lives.

Owner-only: Tier H drafts and Tier H reviews in a fresh read-only context; the
change is then an operator step with complete verification and a human
commit:
- `AGENTS.md` and `.agents/rules/`
- `scripts/` launchers and verifiers (the plan's decision D11b: one
  operator-run, reviewed launcher-and-pins change with a human commit), and
  lock or sync changes: `pyproject.toml`, `uv.lock`, `.python-version`
- the same files in `offline_data/` and `vectorbt_adapter/` (engine isolation)
- `tools/gitnexus/`
- the specification and accepted plans, which `AGENTS.md` makes authoritative

High blast radius: at least Tier M implementation and Tier M review.
- creating, deleting or renaming any file under `src/crypto_lab/`;
- any change under `tests/safety/` or `tests/architecture/`, or to
  `tests/unit/test_package_layout.py` or `tests/unit/test_schema_registry.py`;
- any change to a pinned count, census, allowlist or golden hash, wherever it
  lives. On 2026-11-18 the census is mirrored outside `tests/safety/` in
  `tests/unit/persistence/test_sqlite_database.py`,
  `tests/unit/persistence/test_sqlite_migrations.py`,
  `tests/unit/process_supervision/test_supervisor_preflight.py`,
  `tests/unit/process_supervision/test_restart_reconciliation.py` and
  `tests/unit/artifacts/test_artifact_store.py`;
- pinned prose: a document is pinned when a search of `tests/` finds its path.
  On 2026-11-18 that includes `README.md`, `docs/development/verification.md`,
  the Project 1 master roadmap and the portable-strategy plan, and Task 8's
  planned `docs/development/local-cli.md` and acceptance ledger. `.gitignore`
  text is also pinned.

Mechanical checks before review. Run by command; keep the output with the task
record and give it to the reviewer:
1. Compare `git diff --name-only <base> <commit>` with the plan task's Files
   created and Files modified. Every missing or extra file is a defect or a
   recorded plan deviation.
2. For every old value that the plan task's Guard reconciliation block moves,
   search `tests/` for it in assertion form (for example `== 138`). Resolve
   every remaining hit.
3. Check the block both ways. A row not implemented, or a pinned assertion
   changed outside the block, stops for a plan correction, drafted by a Tier H
   model and committed by the owner. Plan-named pin moves are the only changes
   allowed to existing pinned assertions.

Hydrogen handles ordinary implementation with settled interfaces.
Flash handles bounded low-risk work with explicit acceptance examples.

The previously identified scheduler concerns remain critical until
reinspection proves they are corrected. Read here as: the Stage 10 plan's gate
B3 (durable scheduling and creation idempotency: queue instant, creation
correlation and replay; "durable ordering and creation idempotency" in
`local dump/Crypto_Lab_Antigravity_Handoff_2026-11-16/docs/09_OPEN_ITEMS.md`),
gate B2 on which B3 depends
(application audit vocabulary), and the scheduler claim, retry and requeue
code, present from S10-T4 `2d6f711` on `origin/project-1-stage-10-task-3`
(`src/crypto_lab/experiments/scheduler.py`). "Reinspection" is the plan's D14
reinspection of an owner-approved, integrated correction; D14 itself corrects
nothing. Only the owner or a fresh Tier H reviewer records that reinspection
proves them corrected, citing the commit. If the owner meant other concerns,
name them here.

4. ESCALATE WITHOUT WASTING THE CHEAPER MODEL'S SAVINGS

When a worker encounters a substantive contract ambiguity, escalate immediately.

When a low-cost worker has made an initial attempt and a reasoned correction
but still cannot satisfy the same requirement, escalate rather than repeating
the same approach.

The same applies to review and verification: after two REQUEST_CHANGES rounds
on the same requirement, or a complete-verifier failure that the section 3
checks and focused verification did not predict, escalate one tier (from
Tier H, to the owner) and check the plan task for a gap.

Preserve useful changes and pass a compact evidence packet:
- requirement and relevant production interfaces;
- current diff;
- failing test and exact error;
- approaches tried;
- remaining uncertainty.

Do not make the next model repeat the entire investigation.
Return to the lower-cost model once the difficult question is resolved,
within the task's class; a raised class stays raised.

Missing permissions, missing dependencies and unavailable tools are not
model-reasoning failures. Handle those boundaries directly.

5. REDUCE REPEATED CONTEXT AND REVIEW COST

Supply the relevant task section and code, not the entire repository history.
Every task packet includes the plan task's Files lists and focused
verification commands, and its Guard reconciliation block where it has one.

Keep one concise continuation record with source references, in the
git-ignored `.superpowers/sdd/` directory unless the owner approves a tracked
location; never under `src/`, `tests/` or `scripts/`.
Use targeted file reads and bounded log excerpts; retain complete logs on disk.

Use existing supported caching where available. Do not build a cache framework
or assume cached tokens were billed cheaply without usage evidence.

Use one independent review at the appropriate checkpoint.
Re-review the correction and affected behavior, not unrelated accepted code.

Do not run Flash, Hydrogen and Carbon on every task as a mandatory ladder.
Select the appropriate starting model and escalate only when justified.

6. MEASURE ACTUAL VALUE

For each accepted task, record available:
- model(s) and reasoning settings;
- input, cached-input, output and reasoning usage;
- estimated cost using the applicable dated rate;
- implementation attempts and review corrections;
- elapsed execution time and accepted result.

Record it beside the continuation record (section 5).
Use provider usage metadata where available.
Mark unavailable accounting UNKNOWN, not zero.
Do not double-count reasoning when it is already included in output usage.

Keep rate dates explicit and reassess after promotional pricing ends.
Do not claim a saving by comparing only token prices while excluding rework.

Honor existing billing controls. Do not create new arbitrary turn ceilings,
change spending limits or enable another paid service.

7. KEEP THE EXISTING DELIVERY SAFEGUARDS

No changes to acceptance requirements, security, test assertions,
publication permissions or core/adapter isolation.
This policy changes none of these. The steps below supplement the plan's
acceptance requirements, and plan-named pin moves are part of them.

At most two implementation workers on independent worktrees.
One heavy verifier at a time, with no competing heavy work.

A cheap worker does not approve its own implementation.
An expensive model does not override a failed test.
A passing weak test does not establish the promised behavior.

Dispatch a task only when every task in its Prerequisites line is accepted.
Work stacked on an unaccepted task is not reviewed or verified until that task
is accepted, and is then rechecked on the accepted base.

Before the complete verifier:
- the focused log records `git rev-parse HEAD`, an empty
  `git status --porcelain`, each of the plan task's focused commands verbatim
  and its exit code, and every command passed;
- the section 3 mechanical checks are clean or each deviation is recorded;
- the review approved that same commit.
The focused log, the approved review and the complete verifier name the same
commit. Any later change restarts at the focused checks and a re-review of
that change.

While the complete verifier runs, no worker on any worktree runs tests,
linters, type checkers, builds or other heavy commands, and no source or
toolchain file is edited. Reading and planning may continue.

Acceptance:
- The result is the verifier's exit code and its stored log. A command, not a
  model, extracts the final summary and every failure, skip and warning.
- When the verifier exits 0 and the extract shows no failure and no skip or
  warning beyond the recorded baseline, the extract is the result. Otherwise
  a model at least as strong as the strongest implementer, never the
  implementing session, decides from the stored log. A Tier L summary is an
  index, not evidence. The baseline is the skip and warning set in the last
  accepted verifier log; only the owner or a Tier H model changes it.
- A failure that passes when rerun is not a pass. Record both runs, the
  failing test id and the host conditions, and keep the failure open until it
  is explained and fixed or the owner records a disposition. Never retry until
  green, raise a timeout, add a skip, or stop a process the run did not start.
- A task is accepted when its review approved the commit and the complete
  verifier passed on that commit under these rules. The coordinator records
  the acceptance; it does not decide it.

NEXT ACTION

Reconcile the active task and select the appropriate model without
interrupting an active verifier.

Return:
Role | Actual model | Task | Reason for selection

Then continue the existing task. Do not start another controller project
or repeat completed setup.

APPENDIX: STARTING CLASSES FOR THE REMAINING WORK (2026-11-18)

State on 2026-11-18: `origin/project-1-stage-10-task-3` carries S10-T3
`4631fc6` and S10-T4 `2d6f711`. Neither is accepted, and T4 was stacked on the
unaccepted T3 although the plan requires "Accepted T1-T3". Both still assert
the old census value `== 138` in five unit test files while the guards moved
on (139 at T3, 141 at T4); the section 3 checks flag this.

- Stage 10 Task 3 correction: critical (`experiments/application.py`); the
  census-only test edits are high blast radius. Run the section 3 checks
  first. Besides the census gap, T3 has two plan deviations to resolve: it
  edits `tests/safety/test_stage7_boundaries.py`, outside its Files lists
  (the plan keeps Stage 6/7 guards as unchanged regression targets), and it
  omits the planned Stage 10 pin making `experiments/application.py` the only
  `strategy`/`datasets` importer.
- Task 4 (`2d6f711`, `experiments/scheduler.py`, `cli/execution.py`):
  critical. Not reviewed or verified until T3 is accepted; then rechecked on
  the accepted T3.
- Task 5, operational CLI and concrete composition, including physical
  dataset confinement: critical.
- Task 6, CLI outcome and boundary acceptance matrix: high blast radius (it
  modifies `tests/safety/test_stage10_boundaries.py`); any critical part is
  named by the owner or a Tier H model before dispatch.
- Task 7, restart, killed-child recovery and cleanup evidence: critical.
- Task 8, runbook, acceptance ledger and final evidence: high blast radius
  (pinned prose and acceptance evidence).
- Project 3 plan revision 2 (VectorBT adapter): Tier H (architecture and
  engine isolation).

By the owner's own list most remaining Stage 10 work is critical. The savings
come from Tier L coordination, packets and summaries, Tier M review of
non-critical files and census edits, mechanical checks that cost seconds, and
avoiding failed complete verifier runs.
