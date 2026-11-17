# 8. Verification, review and publication

## Product execution route

The core's authoritative verifier is `scripts/verify.ps1`, through the repository's existing `scripts/invoke-uv.ps1` profiles and managed CPython 3.12. The offline-data verifier is `offline_data/scripts/verify-offline.ps1` with its own isolated environment. Inspect current scripts before invocation and use their real approved syntax.

Do not replace product verification with a system Python `pytest` call. Do not treat a focused `-o addopts=` run as coverage-bearing full acceptance. Keep dependency installations and network bootstrap separate from offline verification.

## Evidence required per authoritative run

Record the intended repository, complete HEAD and candidate manifest/tree, execution-surface identity where relevant, start/end time, native exit, full stdout/stderr, completed stages, collection/pass/fail/skip outcomes, coverage details, review identity and owned-process cleanup. Logs that truncate or lack exits remain incomplete.

The historical verifier had eleven stages, including lock/sync, formatting, lint, typing, generated schemas, migration check, full tests, build, distributed schemas and whitespace. The actual current script is authoritative; do not fake a missing stage from a previous pass.

Coverage floors are stage-specific. P0's measured 98.67% and later 98.66% were reported; do not silently round the baseline down or attribute the difference to randomness without branch-level evidence. The configured 90% floor alone may not satisfy the stage plan. Check the accepted final-baseline rule.

Known skip-capable sites include symlink privilege, same-state replay and Pydantic importorskip. A count of two does not identify skip reasons; Pydantic must not actually skip when it is a locked requirement. Record positional attribution limitations honestly.

## Independent review

Use a separate Antigravity/Google-model context, the exact candidate diff, relevant contracts and test outputs. Ask it to distinguish correctness/security findings from style preferences. Material findings must close. Confirm corrections against previous findings and changed code. An independent context is not independent deterministic evidence; real tests remain mandatory.

## Owning-stage corrections and packaging

Prefer coherent regression-backed corrections. Group corrections with integration when that is the accepted exact subject and no behavior guarantee is obscured. The previous 'separate commit before T8' requirement was explicitly superseded. Do not reintroduce it from old reports.

## Development branch commits

Check the real index first. Stage only accepted paths, including intentional deletions. Run `git diff --cached --check`. Confirm committed paths/blobs match reviewed and verified bytes, with the expected parent. Keep private logs, raw data, model weights, virtual environments and credentials out of Git. Do not amend accepted published history to change a model trailer.

Use the existing approved origin for `PratikRajSingh0612/Crypto_Trading`. Explicit single-branch non-force pushes only. Verify actual remote refs rather than assuming tracking refs are current. A rejected push leaves a valid accepted local commit as publication-pending; it does not require reimplementation.

## Integration/main

Combine actual accepted commits in an isolated integration worktree. Preserve parent identities and histories. Review conflict resolutions. Verify the actual combined tree and relevant consumers, including the installed core package used by offline_data and real r0002 migration behavior. A stale wheel or empty version-stamped database is not integrated acceptance.

Record acceptance from actual evidence. Keep acceptance bookkeeping outside the verified subject or prepare required tracked documentation before final verification. Promote local main by a non-rewriting, expected-ancestor operation; perform required main-checkout verification; publish exact accepted main non-force after rechecking remote ancestry. Unexpected remote divergence is a reconciliation task, never permission to overwrite.

A user-reported local merge is not a verified remote publication. If the old route already completed, preserve its accepted result. Future integration need not invoke its retired model/provider controller: reproduce its deterministic Git/evidence checks directly in Antigravity under the standing authorization.

## Failure handling

Keep FAILED, INTERRUPTED, HOST_NOT_READY and BLOCKED distinct. Do not splice stages from different runs, clear consumed markers or hide adverse outcomes. Diagnose unexpected failures using retained per-launch evidence. Passing after a later correction establishes that candidate, not the causal explanation of every historical intermittent.
