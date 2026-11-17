# 05 - Current handoff: close the actual Stage 8 failure first

## Snapshot, not a reset instruction

Prepared from the user's reports and read-only GitHub observations on 2026-10-31. Local Windows filesystem state is not accessible to the author of this package. Reconcile everything with actual Git and logs before acting.

Repository: PratikRajSingh0612/Crypto_Trading
Primary: C:\Users\59557\Documents\Projects\Crypto_Trading
Active implementation tree: C:\Users\59557\Documents\Projects\Crypto_Trading-worktrees\project-1-stage-8-implementation
Branch: project-1-stage-8-implementation

Last reported local main and implementation HEAD:
e9fdfc3914310fe3ef68cf759583205725c236e7

Task 8 subject: feat: add stage 8 boundaries, documentation and status
Parent / fixed STAGE8_IMPLEMENTATION_COMMIT:
95d39941eb0c20c2621b51af3330bac3c8aef845

GitHub ref check during package preparation:
- implementation branch: e9fdfc3914310fe3ef68cf759583205725c236e7
- remote main: 9bbfffc147a48dbfe4f4fa9e01731f32cb5fdde8

These may change after preparation. Accepted descendant work is to be preserved and consumed, not reset. If the one-file correction is already underway, reconcile its ownership and resume; do not start a competing writer.

## Acceptance status

Stage 8 branch acceptance 20261031-004145-86956 passed: 9342 passed, two approved skips, 98.61%, eleven steps. Its historical unreadable PowerShell PID is an explicit uncertainty, not a proven competing verifier.

Merged-main run 20261031-013130-48972 FAILED: 9341 passed, one failed, two skipped, 98.59%, native exit 1. Steps 1-7 passed; test step failed; build/distribution/whitespace did not execute. It is not accepted and remote main must not be advanced from this evidence.

Failing node:
tests/integration/persistence/test_wal_restart.py::test_an_interrupted_writer_leaves_no_partial_row_after_reopen

Immediate reopen produced PERSISTENCE.STORAGE_UNAVAILABLE, operation open, extended SQLite code 1546 / SQLITE_IOERR_TRUNCATE. The original database, WAL and SHM were preserved; do not open them or alter sidecars. Evidence is under the existing ignored .superpowers/sdd/stage8 directories, with consumed markers retained.

## Completed diagnostics: do not repeat the campaign

The user's report establishes:
- three unchanged focused module runs passed, which does not resolve the intermittent;
- each instrumented Popen represented a uv trampoline, while a different child interpreter owned the SQLite connection;
- the tests killed and awaited the trampoline, but the real holder was alive at the reopen instant;
- controlled first-opener/recovery specimens with a mapped SHM reproduced 1546, including the project's matching diagnostic; releasing that controlled mapping allowed recovery;
- the runtime was CPython 3.12.13 / SQLite 3.53.1, with recorded source identity and binary hashes;
- the exact historical Win32 error, file-level failure and holder state were not captured.

The combined mechanism is well supported, NOT proven for the historical run. Do not generalize to every normal open while another SQLite connection maps SHM. Normal shared-WAL operation is different from the tested first-opener recovery condition.

The historical helper-timeout cause and runtime-level SQLite susceptibility remain open. A fixture correction does not upgrade SQLite or make it immune to external mappings.

## Already authorized correction

Tracked scope ONLY:
tests/integration/persistence/test_wal_restart.py

Implement the test's stated crash checkpoint correctly:
1. Keep the existing sys.executable / isolated flags / no-shell launch shape.
2. The writer stages its existing uncommitted work, flushes readiness with its actual PID, and stays blocked.
3. The parent proves that holder belongs to the live launch and records creation identity while holding a suitable handle. Accept direct-writer and descendant-writer cases; PID alone is insufficient.
4. Preserve the competing-write conflict assertions.
5. Forcibly terminate the actual verified database holder, not the trampoline first; keep the trampoline and stdin alive until this deliberate crash. No EOF or graceful connection-close request may substitute for interruption.
6. Await the actual holder's retained handle with the existing 30-second fixture exit bound; require signaled completion and the specified nonzero forced-exit value. Identity mismatch, timeout, unexpected natural exit or API failure must fail and prevent reopen.
7. Reap the trampoline separately, close all owned resources in finally, and call production reopen exactly once.
8. Preserve the existing committed-row, absent crash_probe, migration/schema, quick_check, WAL and consistency assertions.

Reuse current Windows API/identity helpers; no new ctypes binding or source change. No sleep, reopen retry, sidecar deletion/zeroing, checkpoint workaround, skip, timeout inflation, base-interpreter bypass, dependency acquisition or DLL swap.

Prove the owner/wait/reopen ordering with deterministic controls. RED is the missing owner-exit guarantee, not a demand to reproduce a rare 1546. Wrong-identity tests use safe doubles, never foreign live processes. One focused independent reviewer; a few meaningful negative/mutation controls, not another reviewer swarm or five-clean-run requirement.

If 1546 recurs after signaled owner exit and correct forced termination are proven, preserve that fresh specimen and escalate the new evidence. Do not invent another waiting workaround.

## Landing sequence

After focused gates and final review, prepare a new human-launched branch verifier with fresh evidence/marker. The complete unchanged verifier and coverage >=98.42% are required. No repeated unchanged full-suite gambling.

On acceptance, commit the one file:
test: terminate and await the sqlite writer before recovery
Required parent at the reported base:
e9fdfc3914310fe3ef68cf759583205725c236e7

Then bounded implementation-branch publication, clean local-main --ff-only to the correction, a fresh human-launched merged-main verifier, detailed acceptance and finally explicit remote-main publication. Neither correction nor Task 8 completion replaces STAGE8_IMPLEMENTATION_COMMIT.

Only after this closes may the delivery controller progress to Project 1 Stage 9. Under the adopted standing mandate, do not stop merely because the next milestone needs planning; plan it just in time, review it and continue within the delegated scope.
