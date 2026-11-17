# 07 - Resumability and compact human handoffs

## One source of working state

Reuse the current ignored .superpowers/sdd evidence structure. A small program directory may hold STATE.md, BACKLOG.md and DECISIONS.md after verifying it is actually ignored. Do not modify global Git excludes or force-add it. If no ignored location is permitted, keep these beside this external package and record their exact location.

Do not make those mutable management files an application dependency or new test-count pin. Do not regenerate hundreds of pages of historical ledgers. Keep public release notes separately sanitized within the active milestone's permitted docs.

Suggested STATE.md (about one screen plus pointers):

- verified_at, package_version, active_root/branch/HEAD, primary_main, observed_remote_refs;
- active project/stage/task and owned paths;
- status: PLANNING / IMPLEMENTING / REVIEW / READY_FOR_HUMAN_VERIFIER /
  VERIFYING / VERIFIED / COMMITTED / MERGED_MAIN_PENDING / ACCEPTED / BLOCKED;
- last verified subject identity and evidence prefix; actual exits, skips, coverage;
- pending native process/marker/evidence identity (or none);
- decisions actually approved and acquisition allowance consumed/unconsumed;
- unresolved observations with owner and effect on acceptance;
- exact next action, whether it launches anything, and its required prerequisites.

BACKLOG rows: project, capability, dependency, acceptance evidence, state. An engine not executed is not complete. DECISIONS records source/authority, considered alternatives, accepted choice, reviewer, user gate if any and affected contracts.

Checkpoint after each accepted commit and before compaction/session stop. Reconcile Git and evidence on resume, not memory alone. Never overwrite an unknown dirty tree. Do not rerun an accepted verifier solely because a session changed.

## Human-action formats

HUMAN_ACTION_REQUIRED: VERIFIER
- reviewed subject, exact cwd and one foreground command;
- expected script identity, new evidence prefix/marker;
- readiness-refusal handling and exact result to return;
- explicit statement that no heavy run has been launched by the agent.

HUMAN_ACTION_REQUIRED: ACQUISITION
- precise missing prerequisite and failed authorized offline route;
- package/interpreter/model version, official source, license, size if known;
- exact command, paths changed, network destination and rollback limit;
- metadata resolution and locked distribution acquisition separately where required;
- no execution until granted; no global/permanent approval implied.

HUMAN_ACTION_REQUIRED: DECISION
- one material ambiguity with exact sources;
- recommended option and its scope/security/data consequences;
- alternative and what can proceed independently;
- ask only the unresolved decision, not 'should I continue?'.

BLOCKED_EXTERNAL
- unavailable permission/tool/runtime or unresolved same-issue investigation;
- facts, preserved subject/evidence and what is unverified;
- smallest action required; no invented scheduled continuation.

## Milestone report (keep it concise)

Milestone and state; actual user capability delivered; commit and parent;
local and remote refs; tests/review/coverage; independent live integration
proof; remaining limitations; next authorized action.

Use HUMAN_ACTION_REQUIRED rather than a false completion marker for unrun
verification. Use PARTIAL_RELEASE for a useful but incomplete scope.
Use FULL_PRODUCT_COMPLETE only when the full required acceptance matrix
is genuinely satisfied. Missing mandatory engines/features remain visible.

Progress updates should describe new findings or delivered behavior, not
repeat every command. No promised hours/dates derived from test counts.
