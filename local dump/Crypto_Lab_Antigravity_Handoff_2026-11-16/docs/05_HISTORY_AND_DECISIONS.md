# 5. Development history and lessons

This history is a source-linked synthesis. Available original reports are in `sources/history/`; older broad handoffs are in `sources/legacy/`. Historical stop-after-task and provider instructions are not active policy.

## Project 1 stages

| Stage | Delivered scope | Status in the observed record |
|---|---|---|
| S1 | Repository, Python packaging, offline workflow, verification foundation | Accepted historical stage |
| S2 | GitNexus governance decision | Complete; DISABLED_WITH_EVIDENCE |
| S3 | Canonical values, configuration, identifiers, hashing and schemas | Accepted historical stage |
| S4 | Portable strategy specification, evaluator, capabilities and comparison eligibility | Accepted historical stage |
| S5 | Experiments, run/invocation lifecycle, retries and aggregation | Accepted historical stage |
| S6 | Executable adapter protocol and fake-adapter contract harness | Accepted historical stage |
| S7 | Production Windows supervisor, deadlines, cancellation, ownership and restart reconciliation | Accepted historical stage |
| S8 | SQLite persistence, migrations and durable lifecycle integration | Closed; corrected baseline 079395be |
| S9 | Artifacts, finalization, recovery, provenance, audit and integrated scans | All active tasks published; main 874fb51b in connector snapshot |
| S10 | CLI/application composition and whole-core acceptance | Plan published; T1 published; remainder and blockers open |

Do not infer all historical task names from these summaries. The exact headings are in the controlling plans; `tools/collect_local_context.py` extracts them from the actual checkout with line numbers.

## Stage 8 corrections that must not be lost

Tasks 1-7 delivered database/schema/codecs/registries, lifecycle repositories, reconciliation and real persistence integrations. Tasks 4-6 exposed transaction ownership/failure gaps that were corrected before Task 7.

- Five persistence-owned members originally returned fatal WRITE_FAILED results without poisoning the owner. The correction propagated the first failure into the common transaction scope and preserved release timing.
- Registry, observation and diagnostic reads gained DBAPI translation and owner propagation. Missing-row invariants remained distinct from storage failure.
- Invocation services stopped relabelling non-invariant reader failures as missing rows.
- Pre-handoff row 26 legitimately removed a command root if RUNNING was never reached. The test was corrected based on actual invocation facts and cleanup trace, not by accepting every missing file.
- Interrupted-writer tests originally killed/awaited a trampoline rather than the actual SQLite holder. The accepted correction waits on the proven owner handle. It does not patch SQLite itself or prove hardware power-loss durability.
- C-11/C-12 race statements were clarified when their high-level state machines could not produce the originally described joint race. Lower-level CAS evidence was explicitly labelled as such, not falsely described as executed aggregation.
- WAL-resident database writes cannot be inferred from hashing only the main database file without the specified quiescent checkpoint and independent row checks.

Representative accepted identities: corrective A b174d1de; plan correction B 8b66a749; read correction C 4f71171b; pre-handoff test 9d150ca4; invocation correction dbb55358; Stage 8 implementation 95d39941; status e9fdfc39; final writer-fixture correction/main 079395be. Resolve full identities from actual Git before using them.

## Stage 9 task record

| Task | Scope | Known commit/status |
|---|---|---|
| T1 | Candidate/reference/request/journal contracts and hashes | 1b63214a accepted/published |
| T2 | Audit/log/metric contracts | 1ccae301 accepted/published |
| T3 | Normalized result record family | Conditional branch excluded in execution; now explicit Stage 10 B1 gap |
| T4 | Paths, validation, streaming hashes and artifact store | d4c65d4c accepted/published |
| T5 | Artifact repositories, audit persistence, r0002 migration | b8b71ab1 accepted/published |
| T6 | Finalizer, journal recovery and retention | ab3b6de4 accepted/published |
| T7 | Result registration, evidence producers and manifest | 97f57d6e accepted/published |
| T8 | Supervisor/SQLite/artifact composition and token scans | d3a0793b accepted/published |
| T9 | Boundaries, documentation and status | 874fb51b accepted/published |

Key rulings: renewable lease distinct from the hard deadline; provenance-scoped canonical evidence protection rather than global JSON exemption; test-support supervision traces use LogRecord, with authoritative audit work still open; T8 may include its owning-task corrections in one complete verified commit. The old separate-commit demand was superseded when it conflicted with whole-worktree acceptance.

## Parallel Project 2 record

First slice: scaffold e06d3efd, reader 1976ca00, normalization c13ee357, metadata/CLI 3a47d4c9. Subsequent deliveries: Binance reader 4d70f673, temporary SQLite consumer registration 970c1fb5, residual-carriage-return/entry-point corrections 19d4db1e, readiness brief 5de26812, installed-core-identity check 662ae4df. These are distinct development branches and must be integrated using their real ancestry, not copied over one another.

The first slice went through many literal plan/file-map corrections. The lesson is one consolidated requirements/scope consistency check before acceptance, not another endless plan-review campaign.

## Former automation and time loss

The system evolved from human-launched verifiers into a separate Python development controller with Codex advisor, Claude implementation/review, journals, scoped execution, independent verification, commits, publication and supervised resumption.

User-supplied timing analysis for 4-6 November reported 57h37 stopped, 7h44 mission execution and 52m pilots within a roughly 66h14 window. This is a historical window, not a current throughput benchmark. Stops included permission route, missing environments, incomplete branch/publication allowlists, plan conflicts, resource contention and manual relaunch waits.

The Antigravity takeover must not carry forward unnecessary provider/controller ritual. Preserve actual safety and verified product semantics while simplifying task sequencing, grouping related corrections, scoped reviews and resumption. Model price changes or additional agents do not fix contradictory instructions.

## Recent baseline and model provenance

P0 baseline attempts hit distinct timing/health failures. A two-test-file resource-accounting correction was reviewed, passed one full verification and published as 3e5af186. Three timing observations remain unresolved; a pass did not explain them.

Later worker/reviewer model was reported as Opus 5.5, despite an obsolete Fable trailer on S10-T1. Do not rewrite published history or treat a trailer as authoritative execution metadata. The new system uses Google-only runtime identities and records what actually executed.
