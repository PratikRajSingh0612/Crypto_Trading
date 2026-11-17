# 04 - Delivery loop, verification and Git publication

## The normal loop

Observe the current state -> select the next dependency-ready slice -> read relevant interfaces -> make a compact plan -> obtain the required independent plan/design review -> test first -> implement -> run focused/broader checks -> review the final diff -> correct findings -> accept with actual verification -> commit/publish -> checkpoint -> continue.

Do not finish a turn merely because a routine subtask finished while authorized work is available. Do not promise activity outside the active execution environment.

## Planning and changes

Work in an isolated stage/project worktree, with explicit cwd for every shell, Git, Python and review subprocess. Verify git top-level, branch, HEAD, main, merge base, index and dirty/untracked paths before edits. A coherent later accepted descendant of a snapshot is not an error; inspect its evidence and resume instead of resetting. Preserve unexplained/unowned changes.

Use writing-plans for the next milestone only. Include goal/non-goals, source interfaces, ownership/file map, risks, acquisition choices, schema/migration permissions, test scenarios and commit boundary. Do not prewrite future executable plans against imaginary APIs. Review constructibility through actual builders/fixtures before copying code fences.

Record authorized within-scope file-map adjustments before edits. Broad scope is not permission to weaken architectural guards. A defect touching earlier behavior is a separate correction with regression proof and publication status.

Keep normative contracts single-sourced and generated schemas generated. Old immutable schemas and data remain preserved or explicitly version-migrated within permitted stages. No SQLAlchemy model may silently redefine a canonical contract. No SQL-based shortcut around an application operation just to construct an alleged end-to-end proof.

## Test and failure discipline

Production changes use real RED/GREEN. Tests consuming existing correct behavior may pass initially; call them preservation/characterization rather than fabricating RED. Use deterministic seams and independent oracles. Do not seed the final state that an operation is supposed to produce.

Before broad acceptance, run applicable formatting, lint, strict types, schema generation and migration checks through the reviewed launcher. Scope focused runs without implying they satisfy the global coverage gate. No direct uv run, python.exe, pip, guessed launcher profile or external pytest target.

For failure: preserve native exit/full log/current identities; classify execution refusal, host-readiness refusal, infrastructure interruption, test setup defect, failed assertion, or product defect from evidence. Debug the actual boundary. A familiar exception does not prove a known cause. A failing run stays failing even if a later run succeeds.

A bounded focused diagnostic or materially corrected within-scope implementation may proceed without a fresh human ruling. Do not repeat a full suite on unchanged bytes hoping to pass. For the current WAL correction and outstanding merged-main gate, retain the specific one-file/fresh-marker rules in 05_CURRENT_HANDOFF.md. New full execution after an unexplained failed acceptance needs a justified plan and the external launch handoff, not a hidden automatic retry.

Do not lower coverage, increase product timeouts, add sleeps, skip assertions, delete failed databases/sidecars, replace guarded helpers, or call platform incompatibility a passed case to obtain green. Rerun only for a stated reason; preserve all outcomes and stop when no new evidence distinguishes hypotheses.

## Independent review

Use one fresh focused reviewer by default, or the existing binding plan's required number. Supply stable subject identity and contracts. Require zero Critical and zero blocking Important findings. Minor findings may be fixed or explicitly dispositioned; do not implement all suggestions blindly. Recheck material edits. Record reviewer availability failures honestly.

Review includes truth of docs, public data/secret boundaries, operation ownership and evidence completeness, not only style. A tool such as CodeRabbit or SonarQube does not replace repository acceptance. Do not call optional tools required when they are unconnected or not authorized.

## Heavy verification: retain the proven human-foreground route

This host has a history of background verifier reaping and intermittent load-sensitive failures. Keep full verifiers on the user's separate foreground Windows PowerShell route until an actual approved execution change is tested. Do not use Claude's ! invocation, background command system, endless loop or no-reap/permission bypass setting to circumvent it.

Prepare an accurate minimal launcher/handoff using existing reviewed mechanisms. Pin the current subject, branch and cwd; use a fresh short user-local temp root and fresh evidence identity; keep consumed markers. Reuse helpers, not an old subject's marker/hash expectations. Do not build another framework of wrappers or perform multiple reviewer swarms on a small launch adaptation.

Current approved operator readiness: three valid samples at least ten seconds apart, every CPU reading <=50%, every free-memory reading >=8 GiB. Invalid measurement is not zero CPU. These are launch criteria, not proof of application resource requirements or cause of a prior flake. No live monitoring that changes running-suite semantics. A readiness refusal before the start marker launches no verifier; a later human invocation remains permitted. No automatic polling.

Ordinary closed launcher profiles and the complete verifier stay offline. Use only the specifically approved process-scoped TMPDIR/TEMP/TMP controls and PYTEST_DEBUG_TEMPROOT clearing in the reviewed outer launcher; do not enumerate ambient environment values or grant application environment access.

Run heavy suites alone: no parallel reviews, agent sweeps, other test runners or engine builds. Do not act on foreign CPU consumers or endpoint agents. Unreadable process metadata is UNVERIFIED, not clean and not proof of overlap.

Return HUMAN_ACTION_REQUIRED: VERIFIER with one exact command, cwd, expected subject, log prefix and expected exit handling. Then pause. When the user returns an exit, read matching detailed logs. A wrapper's 0 is not a substitute for all stages, actual totals, skip policy, coverage, builds, distributions, diff checks and task-owned hygiene. Partial runs cannot be joined into a full pass.

The current core acceptance floor is 98.42% branch coverage with the two approved skip sites. Preserve existing commitments; future project-specific gates may add coverage/suites, not quietly weaken the core. The current verifier has eleven stages; later approved tool changes must preserve necessary checks and document their evolution rather than freezing an obsolete count forever.

For new plans, prefer one full acceptance run per coherent reviewed delivery batch and one merged-main run per milestone when required. Avoid a duplicate standalone pytest-all immediately before a verifier containing the identical full suite. Do not silently remove a distinct existing contractual gate.

## Hygiene and evidence

Use identity-bound process ownership and finally cleanup. PID alone is not ownership and a readable process exit code is not a signaled process object. Reap real database/engine holders, close handles/streams/sessions, and prove no task-owned survivors. Do not delete evidence specimens to make the directory look clean.

Distinguish pytest retained bases, uv locks and expected ignored build outputs from leaking command roots, live processes or open sessions. Report denied locations unverified. Preserve failed originals; experiments use fresh owned copies/specimens. Never reopen a failed SQLite specimen casually because opening may alter recovery evidence.

Store machine-private logs, exact local paths and runtime identifiers in existing ignored evidence. Public milestone summaries include only sanitized scope, commit, actual checks, limits and sources. Do not treat regex scanning as a comprehensive secret audit.

## Git and publication

Only the controller stages, commits and pushes. Inspect the exact diff and path set, git diff --cached --check and reviewed/staged/committed identity agreement. No git add ., amend, reset --hard, clean, forced checkout, squash, rebase or history rewrite to repair uncertainty. Keep established commit conventions without forging human coauthorship.

Commit accepted coherent changes. Current one-file correction stays separate above the Task 8 completion commit; historical implementation checkpoint remains fixed. Record locally accepted but unpublished work accurately. Never embed a commit's own unknown SHA into itself.

Destination: PratikRajSingh0612/Crypto_Trading only, using its established origin/authentication. Check effective push destination and unexpected mirrors/rewrites without printing credentials. Normal explicit fast-forward branch pushes and read-only remote-ref checks are authorized; no force, tags, mirror, all-branches push, deletion, repo-settings change or hosted workflow installation.

Publish the active accepted implementation branch. Read actual remote refs and require its SHA to match local accepted HEAD. Do not rely solely on tracking refs. Stop on divergence rather than pulling/rebasing automatically. A remote failure does not invalidate the accepted local commit.

At a stage/project boundary, verify clean primary main at the recorded base and ancestor of the exact accepted commit; merge --ff-only that SHA in the primary checkout; run the independently required merged-main acceptance from that checkout. Only then push main explicitly and verify the remote SHA. Never push pre-acceptance main because README already says complete.

Preserve branches/worktrees; do not apply a skill's cleanup recommendation automatically. At a successful boundary, record clean local and observed remote states and continue to the next authorized prerequisite-ready milestone. No human 'continue' token is required unless a real gate remains.
