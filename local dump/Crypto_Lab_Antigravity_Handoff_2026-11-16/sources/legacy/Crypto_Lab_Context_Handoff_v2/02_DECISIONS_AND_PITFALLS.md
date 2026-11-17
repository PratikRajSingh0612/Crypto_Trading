# Decisions, rationale and lessons worth retaining

This is a selective decision record, not a transcript, new product specification or blanket authorization. Each entry distinguishes enduring constraints, historical corrections and unverified ideas. Read the controlling repository source before changing a contract.

## Product destination and architecture

The user wants the entire local seven-engine research and simulated-trading tool, not a scaffold or mock-only demonstration labelled complete. Project 1 is the fake-adapter-only core; thirteen PROJECTS are the wider destination. Do not confuse those projects with Project 1's ten STAGES.

The approved domain is Binance Spot instruments quoted in USDT, long-only, no leverage, futures, margin, shorting, real-money orders, exchange credentials or withdrawals. Broader vocabulary does not authorize broader execution. No implicit product network behavior. No cloud/Docker/server deployment is authorized by the standing product architecture. Later public-data ingestion must enter through its own approved project boundary. Local UI topology needs its actual later specification; it is not permission to expose a service publicly.

The core owns identity, lifecycle, registry state, provenance and finalization. Engines run in isolated pinned adapter runtimes; they do not import into the core or write its database. Authoritative financial values use Decimal and timestamps use timezone-aware UTC. Strict canonical records reject unknown fields. Stable hashes, immutable queued inputs, terminal-state rules and result/evidence separation must not be weakened.

A reported process exit, manifest or returned outcome alone does not establish success. Eligible results still need core-owned validation and finalization. EVIDENCE cannot turn a failed run into success. Incompatible capabilities are represented honestly, not forced through an engine or resolved by majority voting.

Full planned project order: 1 core; 2 historical data; 3 VectorBT Community; 4 Freqtrade; 5 NautilusTrader; 6 Jesse; 7 OctoBot; 8 Hummingbot; 9 QuantConnect LEAN; 10 risk/hypothetical wallet/paper orchestration; 11 Indian tax/TDS analysis; 12 dashboard; 13 local LLM analysis. The later-project sections are boundaries, not proof of installation or completed detailed plans. Verify actual pinned-engine capabilities when that project is reached. All required features remain on the backlog; one unsupported engine is not silently marked complete.

## Development runtime is not controller runtime

Product work uses the repository's managed CPython 3.12 and closed `scripts/invoke-uv.ps1` profiles. Do not silently use system Python 3.13, direct uv-run bypasses, uncontrolled dotenv/environment configuration or automatic interpreter downloads for product tests.

The separate developer controller was reported built on system Python 3.13 without installing dependencies. That is not a contradiction or permission to migrate the product. Keep SDKs, transport networking, credentials and orchestration state out of crypto_lab and its dependency graph.

GitNexus is DISABLED_WITH_EVIDENCE. Having many GitNexus skills installed does not enable them. Use bounded manual source/reference/diff analysis. Optional cloud/scanning/deployment skills do not independently authorize services, uploads or settings changes.

## Worktrees, commands and evidence

Every process must have an explicit intended cwd and project. A prior audit accidentally depended on shell cwd that could be reset; a passing command in the wrong checkout is not evidence for the intended subject. Check shell cwd, Git root, branch and subject identities. Use exact approved local/remote refs, not only tracking metadata.

Source reviewed, source verified, source staged and source committed must agree. A synthetic or staged blob never present during the run is not covered by that run. Preserve accepted history; do not reset, stash or amend as routine recovery. Keep non-force explicit-branch publication separate from acceptance and remote-main publication after its required gate.

Full tests and heavy verifiers are serial. Reviewer swarms and multiple concurrent suites caused load and unhelpful process complexity. Prefer one writer and one bounded independent reviewer. Ordinary in-scope corrections do not need another human permission prompt; genuine authorization/architecture/acquisition conflicts do.

No success from a partial log, a printed COMPLETE, a model's verdict, or a wrapper exit alone. Native exits, completed required stages, correct subject, actual findings and hygiene matter. A failed/interrupted run stays failed/incomplete even if a subsequent run passes. Do not splice successful stages from different runs.

The last Stage 8 acceptance requirement included 98.42% coverage, eleven steps and the existing two approved skip sites. Those are historical/current-stage facts to check against the governing next plan, not permanent proof that future counts cannot change. A skip count alone does not identify skipped tests. A missing/failed probe is unverified, never zero.

## Readiness, timing and resource identity

Historical readiness wrappers sampled CPU/memory and could exit before verification without consuming a verifier execution. Such operator criteria were not product minimum requirements or causal proof. Consumed markers are never erased to pretend a rerun is a first execution.

Under PowerShell 5.1 strict mode, function output collected for Count needs array semantics (`@(...)`) where zero/one/many results are possible. Parse-checking alone did not catch that runtime behavior. This is a lesson for the existing runner, not a request to redesign wrappers again.

Process ownership is PID plus creation identity and, where needed, a retained handle. A PID alone, process name, image path or disappearance later does not identify historical ownership. A readable exit code is not proof the process object has signaled. Do not touch foreign processes or disable endpoint security based on guesses.

Stage 7 test hygiene was corrected after killing uv launchers during their suspended-child window left fixture orphans. The approved closed termination oracle and test-only natural-exit bound did not increase the production termination bound. Those historical permissions are not reusable permission to inflate arbitrary timeouts.

Row 26's pre-handoff timeout may legitimately remove a command root. The corrected test branches on actual invocation facts and checks absence plus the successful cleanup trace, retaining token-absence checks. A missing request file is not itself a discriminator, and RUNNING-origin cases still need their wire-material proof.

## Persistence corrections now accepted

- Compare-and-swap refusal order was made explicit to match committed contracts: missing/stale stored row before invalid replacement revision step, followed by conditional update and rowcount checking. Do not invent an alternate precedence from an old sketch.
- Fatal member/read failures logically poison their transaction immediately. Later calls return the stored failure without more SQL; physical release follows the approved commit/rollback/context-finally boundary. Do not reintroduce eager release as an assumed requirement.
- Real storage read failures must not be relabelled as missing rows. Missing rows and invariant-coded decode failures have their actual committed contracts; do not replace all failures with empty results.
- Autonomous diagnostics and transaction-owned writes have different lifetimes. Inspect the actual committed interfaces rather than recreating a shared transaction around a process invocation.
- SQLite durability is demonstrated by fresh sessions, independent connection reads and close/reopen as specified; a returned SupervisionOutcome is not persistence proof.
- Hashing a main database file is not enough to observe WAL-resident writes. The accepted Task 7 hash control uses a validated quiescent checkpoint and retains independent row-read proof. Do not generalize that to production checkpointing or deletion of sidecars.

## Race evidence and fixture constructibility

Earlier plans contained scenarios their own state machines could not reach. Prove test construction using real validators/operations before asserting a race. An eligible retry successor can prevent terminal aggregation; a lower-level terminal CAS winner must not be described as an executed aggregation race. The C-12 mover changed snapshot columns without changing the revision. Consult the corrected plan and executable tests for exact claims.

The accepted durable flow uses the required explicit retry policy, slot B's no-decision-required terminal path and slot A's successor/denial sequence. The default configuration did not permit the intended retry. Avoid stale helper examples that violate slot uniqueness, hashes, configured attempt limits or diagnostic correlation.

The supervised SQLite flow explicitly composes real SQLite UoW/recorder/reconciliation components with the production supervisor. It does not secretly use an in-memory OfflineCommandHarness driver. Preserve the independent persistence assertions and no-open-transaction-across-invoke obligations.

## SQLite interrupted writer: closed fixture, open runtime limitation

The older test awaited a uv trampoline rather than the interpreter holding the SQLite connection. Diagnostics observed the owner alive at reopen. Controlled mapped-SHM first-opener/recovery experiments produced code 1546 and succeeded after the deliberate mapping was released; this supports a mechanism but does not observe the historical failing call's Win32 error.

Correction 079395be identifies the actual holder, verifies ownership/creation identity, retains its handle, forcibly terminates that holder, waits on the same handle and checks forced exit before one recovery reopen. It supports both direct-writer and descendant-writer cases. No arbitrary sleep or reopen retry substitutes for the guarantee. Exact implementation is in the committed test; do not rerun its correction instructions.

The fix does NOT patch SQLite, prove every historical failure's cause, guarantee power-loss safety or protect against an unrelated mapped-SHM owner. Avoid the overbroad claim that every ordinary WAL open fails while another client maps SHM. The demonstrated susceptibility concerns the controlled first-opener/recovery condition.

## Why old transcript commands must not remain active

Earlier instructions repeatedly said stop before the next task, disallowed all remote Git, authorized one specific acquisition, constrained a temporary file map or demanded an old commit parent. Some were superseded; others were consumed. Archive them with their scope/status, not as permanent top-level instructions.

The current user wants less human relay and more bounded autonomy. That changes operating intent, not evidence already collected or actual managed tool permissions. The controller cannot authorize its own spending increase, policy rewrite, secret upload or destructive operation from a model response.

API-model identifiers, timeline estimates and pricing recommendations in earlier assistant messages were suggestions, not project requirements. Reverify model availability in the installed transport. Do not encode an old suggested model or unadopted budget as immutable policy.
