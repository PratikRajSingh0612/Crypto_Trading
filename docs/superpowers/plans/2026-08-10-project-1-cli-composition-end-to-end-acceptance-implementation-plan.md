# Project 1 Stage 10 - CLI Composition and End-to-End Acceptance Implementation Plan

**Status:** Revision 2: the five reviewed parts consolidated with every independent-review finding folded; awaiting the final independent review and advisor acceptance; not an acceptance record.

Prepared under the owner's standing authorization of 2026-11-10,
"AUTONOMOUS PROGRAMME DELIVERY".
Implementation status belongs in the roadmap and controller records.
B1 and B2 remain acceptance blockers; B3 is conditional.

**Planning base:** `874fb51b4959ca6c3b8e5a2bc640b9af99b176f1`
(`main`, observed clean HEAD).

**Prerequisites:** Stages 4-9 integrated; P0, P1 and the corrective gates below.

**Goal:** Compose the existing application through explicit local CLI commands
and demonstrate the complete offline Project 1 acceptance matrix.

**Architecture:** `cli` wires concrete implementations;
`experiments` coordinates application-owned ports.

**Tech stack:** Existing managed CPython 3.12, strict Pydantic models,
SQLite, SQLAlchemy, Alembic, Windows supervision and fake adapters.
No new dependency.

**Specification:** `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md`,
all sections, emphasizing sections 7-8, 22, 24-25, 27-30 and 33.

> **For agentic workers:** Implement this plan task by task under the controller.
> Each task has one worker, exact file bounds, independent review and an acceptance gate.
> A proposed interface or selector is an implementation obligation, not existing code.
> A task's bounded acceptance never closes an explicitly blocked programme criterion.

**Reading guide:**

- Global Constraints apply to every prerequisite, task, correction and acceptance.
- Section 1 fixes scope, blockers, delegated decisions and operator prerequisites.
- Section 2 records consumed interfaces and coordinated guard obligations.
- Matrix A in section 3 fixes commands, inputs, configuration, projections and exits.
- Matrix B in section 4 fixes startup order, ownership and recovery barriers.
- Matrix C in section 5 fixes workflow outcomes and per-row prerequisite dispositions.
- Matrix D in section 6 fixes ownership, census changes and documentation reconciliation.
- Section 7 defines test execution routes, evidence keys and all 62 acceptance cells.
- Section 8 supplies executable tasks and their sole worker file-bound paragraphs.
- Section 9 fixes serial verification, integration and the main-publication boundary.
- Section 10 fixes rollback, checkpoints, tokens and completion conditions.
- The Review disposition register records closure of every binding review finding.

Existing-code citations refer to the planning base.
Controller citations use paths relative to this repository into its sibling controller.
Proposed behavior remains UNVERIFIED until executed on the identified subject.
No runtime result is inferred from this planning document.

## Global Constraints

- Preserve every roadmap exclusion, including Stage 10's prohibition on
  unplanned canonical and relational schema changes.
  A discovered schema defect returns to its owning stage through an approved
  corrective plan.
  Source:
  `docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md:276`.

- Owner-held matters include scope/specification or acceptance changes,
  published-schema/request-field changes, security or integrity weakening,
  dependency acquisition, new network access, credentials, policy-floor
  exceptions, publication destinations, force publication and budget increases.
  Delegated technical decisions supply none of those authorizations.
  Sources:
  `../Crypto_Lab_Dev_Controller/config/controller.policy.json:80`,
  `../Crypto_Lab_Dev_Controller/config/controller.policy.json:178`.

- Before implementation or verification, confirm:
  `uv python find --managed-python --system --no-python-downloads 3.12`.
  Stop if unavailable.
  Never download an interpreter or substitute system Python.
  Normal execution uses closed launcher profiles; never invoke `uv run` directly.
  Source: `AGENTS.md:12`.

- Ordinary development and verification remain offline.
  Missing locked packages stop execution after the prescribed offline attempt.
  This plan authorizes no dependency acquisition, network bootstrap,
  engine installation or Project 2 dependency in the core environment.
  Sources: `AGENTS.md:17`, `AGENTS.md:18`, `AGENTS.md:26`.

- Preserve dependencies, development groups, strict typing and coverage settings.
  The four runtime requirements are listed at `pyproject.toml:11`.
  The configured branch-coverage floor is 90 percent:
  `pyproject.toml:96`, `pyproject.toml:105`.

- P0 measures complete-verifier branch coverage on the unchanged planning base
  before implementation.
  Final coverage must meet both that measured baseline and the configured floor.
  Do not round the baseline down, exclude new modules or alter measurement settings.
  Coverage at the planning base is UNVERIFIED.
  T8 records actual baseline, candidate and merged-main evidence.
  Focused runs with `-o addopts=` do not supply acceptance coverage.

- Dispatch one worker per task with an enumerated list of exact repository files.
  Worker bounds appear only in that task's **Files created.** and
  **Files modified.** paragraphs.
  Those paragraphs contain backticked repository-relative file paths only.
  No directory, pattern, implied package marker or prose path is a bound.
  Matrix D describes ownership and reconciliation without creating another bound.

- No worker bound contains a policy-floor file.
  The launcher amendment is operator prerequisite P1, outside worker dispatch.
  The protected AGENTS documentation companion is also operator-owned.
  Controller path enforcement remains independent of the written plan.
  Sources:
  `../Crypto_Lab_Dev_Controller/src/clabctl/policy.py:517`,
  `../Crypto_Lab_Dev_Controller/config/controller.policy.json:156`,
  `../Crypto_Lab_Dev_Controller/config/controller.policy.json:178`.

- Only six launcher profiles are worker-callable:
  `pytest-focused`, `ruff-format-all`, `ruff-check-all`, `mypy-all`,
  `schema-generate-check` and `migration-check`.
  Source:
  `../Crypto_Lab_Dev_Controller/src/clabctl/launcher_hook.py:42`.

- Use the registered executable form, with no chaining, redirection,
  substitution, alternate executable or caller-selected tool:

  ```powershell
  C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/unit/test_cli.py -q
  C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-format-all
  C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-check-all
  C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 mypy-all
  C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 schema-generate-check
  C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 migration-check
  ```

  The focused target above illustrates the invocation shape.
  Each task supplies its own exact targets.
  Registration source:
  `../Crypto_Lab_Dev_Controller/config/controller.policy.json:58`.

- `pytest-all`, `build`, `sync`, the complete verifier and operational
  `cli-local` invocations are operator-run.
  All profiles outside the six-profile hook remain outside worker permission.
  Adding `cli-local` to the product launcher does not add it to that hook.
  Source:
  `../Crypto_Lab_Dev_Controller/src/clabctl/launcher_hook.py:42`.

- Preserve the complete verifier's bytes and eleven-step order.
  Before implementation completion can be claimed, the operator runs:

  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
  ```

  Report every warning, failure, skipped check and unrun later step.
  Partial verification is not a pass.
  Source: `scripts/verify.ps1:21`.

- Keep heavy verification serial under the shared host verifier lock.
  Do not overlap a complete verifier with tests, another verifier, edits or review.
  Retain the full per-task acceptance gate.
  Sources:
  `../Crypto_Lab_Dev_Controller/src/clabctl/relay.py:1187`,
  `../Crypto_Lab_Dev_Controller/README.md:426`.

- Each accepted task requires independent APPROVE review and complete PASSED
  verification covering the same subject bytes.
  The controller commits exactly the accepted manifest on the accepted parent.
  Worker assertions cannot establish acceptance, a commit or publication.
  Source:
  `../Crypto_Lab_Dev_Controller/src/clabctl/gitops.py:323`.

- Implementation-branch publication and main publication are distinct.
  Main publication requires the authorized integration route,
  merged-main verification and the owner-held milestone record.
  A local fast-forward or accepted implementation commit is insufficient.
  Source:
  `../Crypto_Lab_Dev_Controller/README.md:283`.

- The observed controller bindings still name Stage 9 implementation resources.
  The operator must provision reviewed Stage 10 bindings before dispatch.
  This plan grants no worker authority to edit controller policy.
  Current remaining controller-turn capacity is UNVERIFIED.
  Source:
  `../Crypto_Lab_Dev_Controller/config/controller.policy.json:10`.

- For the carried open-handle-count intermittent, permit one isolated rerun
  of the failing command.
  Retain both outcomes and earlier failures.
  A passing rerun does not establish a fix.
  A second failure stops acceptance for diagnosis.
  The exact final subject still requires a PASSED complete verifier.

- Preserve three skip-capable sites:
  symbolic-link privilege at `tests/safety/test_uv_launcher.py:928`;
  same-state replay at
  `tests/unit/experiments/test_experiment_service.py:811`;
  Pydantic `importorskip` at `tests/safety/test_uv_launcher.py:1312`.
  Pydantic must not actually skip.
  These are source sites, not a measured skip-instance count.
  Add no skip, xfail, marker, ignored failure or timeout relaxation.

- Preserve the limitation of positional skip attribution.
  Where the verifier omits reasons, correlate progress positions with collection
  ordering and inventory where possible.
  Label that evidence positional; do not invent reason-level certainty.

- Application modules never inspect ambient environment values or credentials.
  Relevant Python children receive exactly
  `PYDANTIC_DISABLE_PLUGINS=__all__` before Python starts.
  Only the reviewed launcher sets that dependency control.
  Product modules neither inspect nor expose it.
  It is absent from configuration, projections, provenance, audit details
  and hash material.
  Sources: `AGENTS.md:37`, `AGENTS.md:38`,
  `scripts/invoke-uv.ps1:653`, `scripts/invoke-uv.ps1:660`.

- Imports remain free of filesystem operations, clock/entropy draws,
  environment inspection, database initialization and process launch.
  Runtime facilities initialize through explicit calls.
  Fresh-import controls remain fail-closed.
  Source: `tests/unit/test_package_layout.py:376`.

- GitNexus remains `DISABLED_WITH_EVIDENCE`.
  Use manual source, reference and diff inspection.
  Do not install, configure or invoke GitNexus.
  Sources: `tools/gitnexus/outcome.json:4`,
  `docs/decisions/0001-gitnexus-development-tooling.md:28`.

- Stage 10 commit subjects use lowercase wording and the prefixes
  `feat:`, `test:` and `docs:` by design.
  A corrective `fix:` subject is permitted when a recorded corrective task
  actually fixes behavior.
  Use `cli` and `project 1`.

- Plan text contains no developer-specific absolute path.
  Use repository-relative citations, symbolic runtime roots and parameter names.
  The registered executable spelling above is the controller's fixed tool form.
  Runtime absolute-path requirements do not authorize embedding an operator's
  actual directories in this document.

---

## 1. Goal, scope, exclusions, corrective prerequisites and the decision register

### 1.1 Goal and deliverables

Implement local CLI composition, strict explicit configuration,
ordered startup reconciliation, application-service wiring
and offline workflows using existing fake adapters.

Demonstrate success, warnings, incompatibility, unavailability,
crashes, timeouts, cancellation, stale output and recovery.
Preserve generated-schema and migration checks.
Provide operator documentation and the complete offline verification route.

Source:
`docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md:268`.

| Deliverable | Stage 10 responsibility | Owner |
|---|---|---|
| Local commands and configuration | Closed grammar, typed inputs, deterministic configuration and safe results | T3,T5 |
| Startup and recovery | Integrity gates, exclusive reconciliation, scheduling barrier and restart dispatch | T1,T2,T7 |
| Application wiring | Registration, compatibility, queue freeze, scheduling, retries and aggregation | T3,T4 |
| Complete workflows | Production composition, fixture inputs and existing fake adapters | T6,T7 |
| Schema and migration preservation | Registry, migration, generated-byte and distribution checks | T1-T8 |
| Operator evidence | Runbook, criterion ledger, measurements and explicit blocked cells | T8 |

Required evidence includes CLI/composition units, complete contract and Windows
supervisor suites, end-to-end outcomes, restart/crash recovery,
persistence/artifact integrity, security scans, all section 28 categories
and all 62 section 33 criteria.

Sources:
`docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md:278`,
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2305`.

### 1.2 Exclusions and corrective dependencies

The roadmap exclusions remain:

"New architecture; unplanned canonical or relational schema changes; real market
data; real engines/backtests; Binance integration; live or paper trading; wallet,
risk, tax, UI, LLM, Docker, cloud, server, optimization, and promotion features."

A schema defect returns to its owning stage through an approved corrective plan.

Source:
`docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md:276`.

Also exclude credentials, API keys, withdrawals, leverage, futures, margin,
shorting, implicit network access, dependency acquisition
and Project 2 dependencies in the core environment.

Sources: `AGENTS.md:26`, `AGENTS.md:33`, `AGENTS.md:40`.

Introduce no normalized-result converter, Parquet implementation,
engine environment, background service, broker or hidden durable store.
Do not relabel failed results as evidence.
A fixture success, log entry, candidate row or moved file is insufficient
to establish successful acceptance.

**B1 - BLOCKED: required normalized canonical records.**

`CanonicalOrder`, `CanonicalFill`, `PositionSnapshot`, `PortfolioSnapshot`,
`EquityPoint` and supporting names remain deferred.
Stage 9's recorded default did not implement its conditional normalized family.

Sources:
`docs/development/verification.md:1122`,
`tests/safety/test_stage3_boundaries.py:751`.

Missing authorization is an owner-approved owning-stage corrective plan
covering the required canonical contracts, schemas and coordinated guards.

Stage 10 identifies the gap and consumes an integrated correction only after
D14 reinspection.
Meanwhile, 33.2/1, the normalized-family portion of 33.6/8
and 33.6/9 remain NOT CLOSED.

Stage 10 neither adds those records nor reinterprets their criteria.
A normalized-role JSON fixture or existing provenance model supplies
partial evidence only.

**B2 - BLOCKED: application audit vocabulary.**

The closed `AuditAction` enum has artifact/finalization actions
and selected run facts.
It cannot faithfully represent every application fact required by section 30.3.

Sources:
`src/crypto_lab/audit/models.py:61`,
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2214`.

Extending its published schema and relational action constraints
requires an owner-approved owning-stage corrective plan,
migration/compatibility evidence and subsequent D14 reinspection.

Do not overload an unrelated action or call a structured log
an authoritative audit.

Required unsupported fact classes include:

- Strategy and dataset registration.
- Experiment creation, validation, queue freeze and lifecycle transitions.
- Compatibility and approximation decisions.
- Attempt creation, retry decisions/delay, launch and cancellation.
- Invocation creation, lifecycle transitions and write-once enrichment.
- Descriptor registration and negotiation.
- Protocol-event acceptance/rejection and sequence conflicts.
- Database migration and process-reconciliation facts.
- Safety-policy rejection and configuration/hash selection.

These obligations come from section 30.3;
they are not proposed enum members.

Source:
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2216`.

The dispatch rule is explicit:

- If a command would commit a mutation requiring an unavailable authoritative
  action, refuse before that mutation and before launching its child.
- Do not permit the mutation merely by deferring its audit assertion.
- Supported read-only projections may proceed.
- Existing artifact/finalization operations may proceed only where their
  required actions are already faithfully supported and no preceding
  unsupported application mutation is necessary.
- Refusal projections are bounded diagnostics.
  They do not fabricate the unsupported authoritative rejection audit.

Complete create/validate/queue/run setup paths therefore remain blocked
on this base where their required application facts are unavailable.
Matrix C assigns that rule to each row, including inherited setup dependencies.

T3/T4/T5/T6 bounded task acceptance covers precisely the untagged selectors
and refusal paths in their dispatch subjects.
Gated success selectors/facets are authored at D14 reinspection after integration.
They are absent from the current dispatch, not skipped or xfailed.

The tag is:

`(B2-gated: authored at the D14 reinspection after integration; not part of this dispatch)`

An analogous B3 tag identifies conditional durable-fact work.
A selector requiring both carries both gates.

Bounded task acceptance does not close B2 or complete Project 1 acceptance.

**B3 - CONDITIONAL BLOCKER: durable scheduling and creation idempotency.**

`ExperimentRow` has created/updated timestamps and no dedicated queue instant.
`ExperimentCreationRequest` has no correlation field.
Creation stamps time and draws a fresh experiment identity.

Sources:
`src/crypto_lab/persistence/schema.py:514`,
`src/crypto_lab/experiments/requests.py:123`,
`src/crypto_lab/experiments/experiment_service.py:264`.

The delegable branch uses existing durable facts.

Capture the instant the QUEUED CAS stamps, inside the same transaction.
Retain that instant's association with the immutable queued spec.
Do not derive queue order later from the row's mutable `updated_at_utc`.

The queue CAS supplies its replacement timestamp at
`src/crypto_lab/experiments/experiment_service.py:483`.

The candidate design is:

- An atomic, faithfully typed queue audit fact retains the original CAS instant.
- A correlated creation lookup finds the prior operation.
- Replay reconstructs requested spec material using the stored creation instant.
- Replay compares the existing named-profile spec hash before drawing identity.
- Contradictory or missing durable facts cause a stable refusal.

This depends on B2 and independent restart, crash, replay and ordering proof.
It is a proposed interpretation, UNVERIFIED, and does not close B3.

Normative requirements remain:
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:207`,
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2196`.

If existing durable facts cannot prove those guarantees,
the owner-held branch requires an approved owning-stage correction for
a queue column, request field, schema/migration change
or specification amendment.

Stage 10 adds none silently.
Creation time, later update time and an in-memory cache cannot discharge B3.

The B3 tag is:

`(B3-gated: authored at the D14 reinspection after integration; not part of this dispatch)`

### 1.3 Decision register

Every decision below is an
**OWNER-DELEGATED TECHNICAL DECISION**:
a model decision under standing delegation, not a human message.

Plan acceptance records the selected engineering interpretation.
It supplies no missing owner-held authorization for B1, B2 or B3.

Use only the controller's seven classes:

`commit_grouping`, `correction_ordering`, `task_sequencing`,
`file_map_correction`, `state_reconciliation`, `plan_wording`,
`implementation_interpretation`.

Source:
`../Crypto_Lab_Dev_Controller/config/controller.policy.json:81`.

| ID / class | Subject | Selected interpretation |
|---|---|---|
| D01 / implementation_interpretation | CLI grammar and reporting | Matrix A fixes typed commands, explicit base, outputs and exits; no executable or shell override |
| D02 / implementation_interpretation | Catalog bootstrap identity | T3 constructs entries from by-value fields; validate reserved `engine_identity` as `EngineIdentity`; descriptor/slot agreement required |
| D03 / implementation_interpretation | Clocks and identities | Runtime-only UTC/monotonic clock, entropy-backed UUID4 IDs and tokens; injected doubles; no import-time draws |
| D04 / implementation_interpretation | Local ownership and cancellation | Windows named mutex keyed by canonical database identity; process-released ownership; durable CAS; scoped cancellation |
| D05 / implementation_interpretation | Atomic application facts | Transaction-joining facade preserves existing service signatures; audit refusal rolls back associated mutations; no transaction spans I/O |
| D06 / implementation_interpretation | Supervision boundary | Scheduler consumes a structural execution port; CLI execution bridge invokes/destructures the concrete supervisor |
| D07 / implementation_interpretation | Startup order | Ordered journal/process/run/recovery/requeue/sweep phases under one owner; closed internal artifact phase selector |
| D08 / implementation_interpretation | Conditional B3 branch | Original QUEUED-CAS instant plus stored-spec replay; B2-dependent durable proof; no hidden store/schema |
| D09 / implementation_interpretation | Acceptance evidence | CLI matrices, actual overlap, pre-cleanup survivor observation and conformant VALIDATE exact-byte scans |
| D10 / file_map_correction | Guards and ownership | Exact module import budgets, coordinated census mirrors, CLI persistence carve-out and preserved negative controls |
| D11 / task_sequencing | Launcher timing | P1 follows concrete reviewed grammar and closes before T6 dispatch |
| D11 / commit_grouping | Launcher commit | One operator-run reviewed launcher-and-pins change; human commit; hook re-pin before dependent dispatch |
| D12 / plan_wording | Status and documentation | Plan approval is plan-only; T8 reconciles truthful status with blocked cells visible |
| D13 / state_reconciliation | Resumed delivery records | Match parent, manifest, subject bytes and accepted evidence; never infer acceptance/publication |
| D14 / correction_ordering | Corrective dependencies | Reinspect integrated corrections; revise interfaces, counts, pins and gated dispatch subjects before use |

D04 retains dispatch ownership across startup and local driving.
Its nested reconciliation phase releases before normal scheduling.
A competing dispatcher receives a stable contention result.
It never adopts work using a PID or directory name.

The cancellation control route may perform its bounded durable CAS
while a dispatcher owns the database.
It neither reconciles nor launches behind that owner.

D05 preserves the six-member application repository port
and existing service signatures.
A joining facade may defer inner commits.
It must handle inner `finally` rollback, lost CAS, outer failure
and independent-reader visibility without splitting a command's facts.

Sources:
`src/crypto_lab/experiments/ports.py:244`,
`src/crypto_lab/experiments/experiment_service.py:440`.

D10 releases dependency direction only where required for composition.
It does not permit concrete persistence in application services
or concrete supervision types in scheduler ports.

D12 does not turn a proposed plan or bounded implementation delivery
into an acceptance record.

### 1.4 Numbered prerequisites, including the operator launcher step

**P0 - Establish the executable planning baseline.**

After final independent plan review and advisor acceptance:

1. Record the accepted plan identity.
2. Preserve the plan-only approval commit.
3. Provision the reviewed Stage 10 implementation/controller binding.
4. Confirm managed CPython 3.12 and offline prerequisites.
5. Run the unchanged-base complete verifier serially.
6. Record actual unrounded coverage, counts, skips, warnings and elapsed time.
7. Record any failure and unrun later steps.
8. Confirm authorized remaining controller capacity before dispatch.

The unchanged execution baseline is
`874fb51b4959ca6c3b8e5a2bc640b9af99b176f1`.
A plan-only descendant does not introduce a different product-code baseline.
Identify both commits when recording evidence.

No current runtime pass, cache completeness, budget extension
or corrective integration is inferred.

**P1 - Operator-run launcher amendment, one reviewed commit.**

P1 is outside every worker bound.
It follows T5's concrete reviewed grammar and closes before T6 dispatch.
Earlier execution requires an independently reviewed equivalent grammar.

Consumers are T8's runbook and the operator acceptance demonstration.
T6/T7 never invoke `cli-local`.

1. Preserve the current launcher as the byte-level comparison subject.
   Its observed raw SHA-256 and normalized test pin agree:

   `4c2bec40d162168bb8084de7115510181d6f61ad62634ce695742996f5e4022c`

   Normalization removes trailing whitespace from each line
   and joins the lines with LF plus one final LF.
   Sources:
   `tests/safety/test_uv_launcher.py:15`,
   `tests/safety/test_uv_launcher.py:200`.

2. Add exactly one nested operation clause, `cli-local`,
   and a closed argument validator implementing Matrix A.
   Reject surplus tokens, arbitrary modules/scripts/tools, uv flags,
   caller-selected Python, shell command strings and passthrough options.

3. Path-valued tokens are admitted only as one absolute local Windows path
   each: drive-letter root; no UNC or device prefix; no wildcard,
   control character or newline; no leading `-`.

   The PowerShell validator checks token shapes against the closed
   command/flag vocabulary only.
   It never interprets filesystem or product semantics;
   the CLI validates those.

   Preserve each admitted path as one argument.

   This is the first profile forwarding caller-supplied absolute paths.
   The plan accepts that design change under 33.7/2.

   `_ALLOWED_COMMANDS` moves only if the validator introduces a command AST entry.
   Source: `tests/safety/test_uv_launcher.py:18`.

4. Synthesize the existing offline run prefix followed by pinned project Python,
   `-I`, `-B`, `-m`, `crypto_lab.cli` and the validated argument array.
   Preserve interpreter confinement, no-sync/no-dotenv controls,
   fixed environment-removal names, unconditional Pydantic literal
   and native exit propagation.

   Sources:
   `scripts/invoke-uv.ps1:178`,
   `scripts/invoke-uv.ps1:466`,
   `scripts/invoke-uv.ps1:653`,
   `scripts/invoke-uv.ps1:660`.

5. The single operator change covers the launcher implementation
   and its three existing pin owners.
   The implementation is `scripts/invoke-uv.ps1`.
   Launcher behavior/hash/partition pins are at
   `tests/safety/test_uv_launcher.py:15`.
   The operation equality is at
   `tests/safety/test_stage8_boundaries.py:1075`.
   The migration/verifier cross-pin is at
   `tests/unit/persistence/test_sqlite_migrations.py:1072`.

   These four paths form the operator change record.
   They are not a worker dispatch manifest.

6. Add `cli-local` to the targeted-operation partition.
   Advance product operations 21 -> 22.
   Update the normalized SHA pin.
   Add exact argv, path admission, rejection, argument preservation,
   environment-policy and exit-propagation assertions.

   Preserve five bootstrap profiles and both closed switch partitions.
   Sources:
   `tests/safety/test_uv_launcher.py:31`,
   `tests/safety/test_uv_launcher.py:478`.

7. Advance the Stage 8 operation equality only when the new operation exists.
   Source: `tests/safety/test_stage8_boundaries.py:1075`.

8. At the migration cross-pin, add a targeted-membership assertion only.
   Do not add `cli-local` to `_PYTHON_BEARING_OPERATIONS`.
   Preserve that sorted operation tuple, migration-check text,
   verifier neighbors and eleven-step assertions.

   Source:
   `tests/unit/persistence/test_sqlite_migrations.py:1072`.

9. Obtain independent review of the exact patch and post-change raw/normalized
   hashes, complete operator verification and the human commit.
   Future hashes and commit identities are UNVERIFIED.

10. Re-pin the controller launcher binding from the committed raw bytes.
    Before dependent dispatch, prove old-byte refusal and new-byte acceptance
    for the same six worker profiles.
    Keep `cli-local` outside the hook allowlist.

    Source:
    `../Crypto_Lab_Dev_Controller/src/clabctl/launcher_hook.py:9`.

P1 changes neither verifier bytes nor step order.
Its result is 22 product profiles and six worker-callable profiles.

T8 owns README text outside the pinned Local setup block
and the verification-guide profile documentation.
A separately reviewed, verified, human-committed operator companion
updates the protected AGENTS launcher paragraph before T8's worker base.
It changes documentation only and grants no new execution authority.

Sources:
`AGENTS.md:17`,
`tests/safety/test_stage3_boundaries.py:1132`,
`../Crypto_Lab_Dev_Controller/config/controller.policy.json:164`.

Until those documentation edits land,
identify the inherited 21-profile description as stale.
Do not use stale prose as current operational authority.

**P2 - Corrective integration gates.**

Resolve B1/B2 and, when required, B3 through approved owning-stage routes.
Reinspect integrated bytes before refreshing a dependent dispatch.

Independent composition and refusal work may proceed.
Full Project 1 acceptance may not.

D14 refreshes:

- Consumed signatures and types.
- Registry/schema/action/table counts and membership.
- Migration head and compatibility evidence.
- Guard arithmetic and source-text mirrors.
- Gated selectors/facets and concrete task subjects.
- Criterion dispositions and downstream verification targets.

An integrated correction is observed evidence,
not permission to invent its expected future interface.

### 1.5 Stage 9 forward obligations and dispositions

The existing forward-obligation record remains authoritative history.

Sources:
`docs/development/verification.md:1133`,
`docs/development/verification.md:1158`.

| Obligation | Stage 10 disposition |
|---|---|
| DATASET/STRATEGY/EXPERIMENT input evidence | T3 coordinates canonical source/registry qualification; T5 supplies concrete confined readers and composition |
| SYSTEM evidence | T3-T5 select existing production routes; audit-derived content remains B2-gated |
| Application audit emission and aggregate reasons | T3/T4 after B2 integration; required facts share the associated mutation transaction |
| Production supervision trace projection | T4 CLI execution bridge projects structured facts; logs do not discharge authoritative audit |
| Startup order, lease and requeue | T1/T2/T4/T7 prove the complete barrier and ownership lifetime |
| Live RUNNING PID-reuse finding | Required platform cell remains open; a defect returns to Stage 7 correction |
| Physical dataset/strategy input confinement | T5 concrete readers; T3 specifies and tests the reader contract with in-memory doubles |
| Retention command | T5 exposes existing single-entry quarantine purge |
| Retention-limit audit snapshot | T3/T5 after B2; no unrelated action substitution |
| Console/evidence projection | T5 bounded projections distinguish RESULT/EVIDENCE; no dashboard/export service |
| Backup checkpoint | T8 documents a mutually consistent checkpoint; no backup/restore tool |
| Artifact correction operation | Deferred; no mutation of immutable refs or replacement command |
| Normalized producer | Owning later/corrective route; B1 remains visible |
| Diagnostic-reference foreign keys | Owning corrective route; preserve existing zero-dangling controls |
| Survivor evidence limit | T7 observes matching survivors before cleanup |
| Conformant VALIDATE byte-scan limit | T6/T7 independently scan the token-bearing command roots and persisted surfaces |

T3 creates no concrete physical CLI reader.
Its input-boundary tests exercise the reader-contract and typed-input refusal seam
of `experiments/application.py` using in-memory doubles.
T5 implements physical confinement in `cli/composition.py`.

Backup scope is specified at
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2194`.

A documented deferral does not satisfy an acceptance criterion.
Historical Stage 9 results and limitations remain unchanged.
T8 appends new closure evidence outside the byte-pinned historical passage.

---

## 2. Authority, consumed interfaces, readings and reconciliation

### 2.1 Authority and observation boundary

The specification and roadmap govern scope and guarantees.
Reviewed source establishes consumed interfaces.
AGENTS, ADR 0001 and the verification guide supply execution rules
and carried evidence.

The roadmap requires planning against observed interfaces.

Source:
`docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md:351`.

The checkout was observed clean on `main` at the planning base.
This revision turn runs no project Python, tests, schema generator,
build, launcher profile or complete verifier.
It reads no `.venv` contents and changes no repository file.

Interpreter availability, installed-state evidence,
measured baseline coverage and runtime results remain UNVERIFIED.

### 2.2 Observed public entry points and application interfaces

The signatures below describe existing source.
Proposed operational commands are specified separately.

`MISSING` retains its sentinel meaning.
Do not silently replace it with null.

| Existing callable / signature | Source |
|---|---|
| `build_parser() -> argparse.ArgumentParser` | `src/crypto_lab/cli/main.py:12` |
| `main(argv: Sequence[str] \| None = None) -> int` | `src/crypto_lab/cli/main.py:26` |
| Console target `crypto-lab = "crypto_lab.cli.main:main"` | `pyproject.toml:19` |
| Module entry point imports and calls `main` | `src/crypto_lab/cli/__main__.py:3` |
| `load_configuration(*, primary_path: Path \| None, local_override_path: Path \| None, cli_overrides: CliOverrides \| None, invocation_base: Path) -> ApplicationConfig` | `src/crypto_lab/configuration/loader.py:141` |
| `ConfigurationError(code: str, path: Path \| None = None)` | `src/crypto_lab/configuration/loader.py:20` |
| `snapshot_configuration(config: ApplicationConfig) -> ConfigSnapshot` | `src/crypto_lab/configuration/snapshot.py:92` |
| `configuration_audit_hash(config: ApplicationConfig) -> Sha256` | `src/crypto_lab/configuration/snapshot.py:84` |
| `material_base_configuration_hash(config: ApplicationConfig) -> Sha256` | `src/crypto_lab/configuration/snapshot.py:88` |
| Static `StrategyLoader.load(source: bytes, source_name: SourceName, observed_at_utc: datetime) -> Result[StrategyVersion]` | `src/crypto_lab/strategy/loader.py:279` |
| Static `CompatibilityResolver.resolve(requirements: tuple[CapabilityRequirement, ...], descriptor: AdapterDescriptor, availability: RuntimeAvailabilityObservation, comparison_level: ComparisonLevel, policy: CompatibilityPolicy, approximations: tuple[ApproximationDeclaration, ...]) -> Result[CompatibilityResult]` | `src/crypto_lab/capabilities/resolver.py:303` |
| `FrozenAdapterCatalog(entries: tuple[AdapterCatalogEntry, ...], *, clock: Clock)` | `src/crypto_lab/adapters/catalog.py:131` |
| Catalog `get(self, adapter_name: str, adapter_version: str) -> Result[AdapterCatalogEntry]` | `src/crypto_lab/adapters/catalog.py:166` |
| Catalog `list_registered(self) -> tuple[AdapterCatalogEntry, ...]` | `src/crypto_lab/adapters/catalog.py:131` |
| `create_experiment(request: ExperimentCreationRequest, *, unit_of_work: UnitOfWork, clock: Clock, identity_source: IdentitySource) -> Result[ExperimentRecord]` | `src/crypto_lab/experiments/experiment_service.py:264` |
| `queue_experiment(request: ExperimentQueueRequest, *, unit_of_work: UnitOfWork, clock: Clock) -> Result[ExperimentRecord]` | `src/crypto_lab/experiments/experiment_service.py:440` |
| `cancel_experiment(request: CancelExperimentRequest, *, unit_of_work: UnitOfWork, clock: Clock) -> Result[ExperimentRecord]` | `src/crypto_lab/experiments/experiment_service.py:501` |
| `create_attempt(request: AttemptCreationRequest, *, unit_of_work: UnitOfWork, clock: Clock, identity_source: IdentitySource) -> Result[AttemptCreation]` | `src/crypto_lab/experiments/run_service.py:348` |
| `create_invocation(request: InvocationCreationRequest, *, unit_of_work: UnitOfWork, clock: Clock, identity_source: IdentitySource) -> Result[CommandInvocationRecord]` | `src/crypto_lab/experiments/invocation_service.py:468` |
| `evaluate_retry(request: RetryEvaluationRequest, *, unit_of_work: UnitOfWork, clock: Clock) -> Result[RetryDecisionRecord]` | `src/crypto_lab/experiments/retry.py:513` |
| `successor_is_due(decision: RetryDecisionRecord, *, now: datetime) -> bool` | `src/crypto_lab/experiments/retry.py:685` |
| `create_successor(request: SuccessorCreationRequest, *, unit_of_work: UnitOfWork, clock: Clock, identity_source: IdentitySource) -> Result[AttemptCreation]` | `src/crypto_lab/experiments/retry.py:698` |
| `aggregate_experiment(request: ExperimentAggregationRequest, *, unit_of_work: UnitOfWork, clock: Clock) -> Result[ExperimentAggregationResult]` | `src/crypto_lab/experiments/aggregation.py:385` |
| `Stage5InvocationLifecycle(*, unit_of_work: UnitOfWork, clock: Clock, diagnostics: DiagnosticRecorder)` | `src/crypto_lab/experiments/supervision_lifecycle.py:346` |
| Lifecycle `register_request_material(self, invocation_id: InvocationId, material: RequestMaterial) -> None` | `src/crypto_lab/experiments/supervision_lifecycle.py:354` |
| `ComparisonEligibilityService.evaluate(self, left: RunManifest, right: RunManifest, requested_level: ComparisonLevel) -> ComparisonEligibilityResult` | `src/crypto_lab/experiments/comparison.py:136` |

The current CLI is version/help-only.
It does not yet compose an operational application.

Source: `src/crypto_lab/cli/main.py:26`.

Protocol negotiation remains:

`negotiate_protocol(envelope: BootstrapDescriptorEnvelope, support: CoreProtocolSupport = CORE_PROTOCOL_SUPPORT) -> NegotiationResult`

Source: `src/crypto_lab/adapters/negotiation.py:605`.

`CORE_PROTOCOL_SUPPORT` supplies the existing protocol/schema selections,
`capabilities/v1` and `negotiation/v1`.
Composition invents no protocol.

Source: `src/crypto_lab/adapters/negotiation.py:406`.

### 2.3 Configuration path and explicit catalog identity

Use this precedence:

compiled defaults -> explicit primary TOML -> explicit local override
-> typed `CliOverrides`.

A local override requires a primary.
Primary/override source paths and invocation base are absolute.
Relative TOML roots resolve against the primary file's parent,
otherwise the explicit invocation base.

Source: `src/crypto_lab/configuration/loader.py:141`.

Queueing freezes the existing complete `ConfigSnapshot`,
configuration audit hash and material-base hash with the immutable spec.
Operational paths/concurrency remain in the complete audit snapshot.
The material projection retains retry, process, protocol,
stderr-budget and policy settings.

Sources:
`src/crypto_lab/configuration/snapshot.py:19`,
`src/crypto_lab/configuration/snapshot.py:63`.

`AdapterEntryConfig` has no `engine` field.
`AdapterCatalogEntry` requires one.

Sources:
`src/crypto_lab/configuration/models.py:390`,
`src/crypto_lab/adapters/catalog.py:87`.

**Proposed D02 contract:**

T3's `experiments/application.py` exposes catalog-entry construction
over by-value configuration fields:

- Adapter name.
- Adapter version.
- Executable path.
- Executable hash.
- Copied runtime metadata mapping.

`cli/composition.py` supplies those values at T5.
Application code imports no configuration module/model.

Validate `runtime_metadata["engine_identity"]`
as `crypto_lab.domain.experiment.EngineIdentity`,
with exactly `engine_name` and `engine_version`.

Source: `src/crypto_lab/domain/experiment.py:122`.

Remove the reserved `engine_identity` key from the copied metadata
before constructing `AdapterCatalogEntry`.
Preserve the original complete configuration snapshot unchanged.

Missing, extra, malformed or conflicting identity data,
executable-path incompatibility, metadata retyping failure
or any catalog-construction failure produces the proposed stable refusal
`CONFIG.CATALOG_ENTRY_INVALID`.

Do not infer identity from a filename, adapter name or executable inspection.
T5 projects T3's refusal and verifies agreement with the observed descriptor
and every selected slot.
It does not duplicate T3's catalog-construction implementation.

This convention uses an existing bounded metadata field.
It adds no canonical/configuration field or environment entry.

Source:
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:1616`.

### 2.4 Persistence, supervision, artifact and audit surfaces

| Existing surface / signature | Source |
|---|---|
| `open_database(path: Path, *, busy_timeout_ms: int, clock: Clock) -> Result[SqliteDatabase]` | `src/crypto_lab/persistence/migration_runner.py:227` |
| `open_for_migration(path: Path, *, busy_timeout_ms: int, clock: Clock) -> Result[SqliteDatabase]` | `src/crypto_lab/persistence/migration_runner.py:254` |
| `apply_migrations(database: SqliteDatabase, *, script_location: Path \| None = None) -> Result[RevisionReport]` | `src/crypto_lab/persistence/migration_runner.py:318` |
| `SqliteUnitOfWork(database: SqliteDatabase, clock: Clock)` | `src/crypto_lab/persistence/unit_of_work.py:605` |
| UoW `begin(self) -> SqliteTransaction` | `src/crypto_lab/persistence/unit_of_work.py:610` |
| Database `consistency_report(self) -> ConsistencyReport` | `src/crypto_lab/persistence/database.py:657` |
| Database `close(self) -> None` | `src/crypto_lab/persistence/database.py:705` |
| Snapshot writer `freeze(self, experiment_id: ExperimentId, snapshot: ConfigSnapshot) -> Result[None]` | `src/crypto_lab/persistence/registries.py:637` |
| Strategy repository `register(self, version: StrategyVersion) -> Result[None]` | `src/crypto_lab/persistence/registries.py:777` |
| Dataset repository `register(self, descriptor: DatasetDescriptor, partitions: tuple[DatasetPartition, ...]) -> Result[None]` | `src/crypto_lab/persistence/registries.py:901` |
| `SqliteReconciliationSource(database: SqliteDatabase, clock: Clock)` | `src/crypto_lab/persistence/reconciliation_source.py:144` |
| Source `list_reconciliation_targets(self) -> Result[tuple[CommandInvocationRecord, ...]]` | `src/crypto_lab/persistence/reconciliation_source.py:148` |
| Source `run_facts(self, run_id: RunId) -> Result[RunReconciliationFacts]` | `src/crypto_lab/persistence/reconciliation_source.py:148` |
| Supervisor `async invoke(self, command: AdapterCommand, cancellation: CancellationToken) -> Result[SupervisionOutcome]` | `src/crypto_lab/process_supervision/supervisor.py:365` |
| `ArtifactStore.open(staging_root: Path, artifacts_root: Path, quarantine_root: Path, *, now_utc: datetime, hasher: ContentHasher \| None = None) -> Result[ArtifactStore]` | `src/crypto_lab/artifacts/store.py:543` |
| `JsonLinesLogWriter.open(logs_root: Path, *, retained_files: int, clock: Clock, file_bytes: int = LOG_FILE_BYTES) -> Result[JsonLinesLogWriter]` | `src/crypto_lab/audit/jsonl.py:163` |
| Log writer `write(self, record: LogRecord) -> Result[None]` | `src/crypto_lab/audit/jsonl.py:221` |
| `AuditSink.append(self, event: AuditEvent) -> Result[None]` | `src/crypto_lab/audit/sink.py:31` |
| Transaction-bound audit implementation | `src/crypto_lab/persistence/audit_sink.py:128` |

CLI commands expose no migration `script_location` override.

`WindowsProcessSupervisor` constructor:

```text
WindowsProcessSupervisor(
    *,
    lifecycle: InvocationLifecycle,
    controller: ProcessController,
    clock: Clock,
    supervision_root: str,
    supervisor_instance_id: str,
    cancellation_grace_seconds: int = 10,
    describe_limits: ProtocolLimits = PROTOCOL_LIMITS_DEFAULT,
    preflight: PathPreflight | MISSING = MISSING,
    observers: tuple[SupervisionObserver, ...] = (),
)
```

Source: `src/crypto_lab/process_supervision/supervisor.py:314`.

Its `invoke` already uses `asyncio.to_thread`.

Source: `src/crypto_lab/process_supervision/supervisor.py:365`.

Process recovery:

```text
reconcile_invocations(
    *,
    source: ReconciliationSource,
    lifecycle: InvocationLifecycle,
    controller: ProcessController,
    preflight: PathPreflight,
    clock: Clock,
    supervisor_instance_id: str,
    observer: SupervisionObserver | MISSING,
) -> Result[ReconciliationReport]
```

Source: `src/crypto_lab/process_supervision/reconciliation.py:782`.

Artifact finalizer:

```text
CoreArtifactFinalizer(
    unit_of_work_factory: UnitOfWorkFactory,
    clock: Clock,
    hasher: ContentHasher,
    store: ArtifactStore,
    probe: FinalizationProbe,
    registrar: PurposeRegistrar,
    auditor: FinalizationAuditor,
    *,
    command_roots: CommandRootsLookup,
    token_material: TokenMaterialLookup,
    log: FinalizationLog | None = None,
    ceilings: ValidationCeilings = DEFAULT_CEILINGS,
    fail_run_on_abandon: bool = False,
)

async finalize(
    self,
    request: FinalizationRequest,
    cancellation: CancellationToken,
    *,
    token_material: AttemptTokenMaterial | MISSING = MISSING,
) -> Result[FinalizationResult]
```

Sources:
`src/crypto_lab/artifacts/finalizer.py:766`,
`src/crypto_lab/artifacts/finalizer.py:812`.

Existing artifact recovery:

```text
reconcile_finalization(
    *,
    unit_of_work_factory: UnitOfWorkFactory,
    store: ArtifactStore,
    hasher: ContentHasher,
    registrar: PurposeRegistrar,
    recovery_validator: ResultRecoveryValidator,
    auditor: FinalizationAuditor,
    clock: Clock,
    runtime_root: Path,
    command_roots: CommandRootsLookup,
    token_material: TokenMaterialLookup,
    log: FinalizationLog | None = None,
) -> Result[FinalizationReconciliationReport]
```

Source: `src/crypto_lab/artifacts/recovery.py:1408`.

Caller-held reconciliation exclusion and a scheduling barrier
are existing preconditions.
T2 adds the proposed closed keyword-only internal phase selector.
The omitted-selector complete pass remains unchanged.

Single-entry quarantine retention:

```text
purge_quarantine(
    entry_id: str,
    correlation: str,
    *,
    store: ArtifactStore,
    unit_of_work_factory: UnitOfWorkFactory,
    auditor: FinalizationAuditor,
    clock: Clock,
) -> Result[None]
```

Source: `src/crypto_lab/artifacts/recovery.py:1445`.

Application conclusion:

```text
conclude_command(
    outcome: SemanticOutcome,
    command_result: CommandResult,
    output_parse: ValidationResultParse | ManifestParse | MISSING,
    protocol_summary: ProtocolEventSummary,
    observations: tuple[CandidateObservation, ...],
    *,
    roots: CommandRootPaths,
    token: AttemptTokenMaterial | MISSING,
    config: ConclusionConfig,
    unit_of_work: ConclusionUnitOfWork,
    finalizer: ArtifactFinalizer,
    clock: Clock,
) -> Result[CommandConclusion]
```

Source: `src/crypto_lab/experiments/finalization.py:3690`.

DESCRIBE conclusion:

```text
conclude_describe(
    command_result: CommandResult,
    descriptor_parse: DescriptorParse | MISSING,
    reconciliation: SemanticReconciliation,
    *,
    roots: CommandRootPaths,
    config: ConclusionConfig,
    unit_of_work: ConclusionUnitOfWork,
    finalizer: ArtifactFinalizer,
    clock: Clock,
) -> Result[tuple[ArtifactRef, ...]]
```

Source: `src/crypto_lab/experiments/finalization.py:3973`.

Candidate observation:

```text
observe_candidates(
    work_dir: Path,
    declarations: Sequence[str],
    token: AttemptTokenMaterial | MISSING,
    *,
    hasher: ContentHasher,
    clock: Clock,
) -> Result[tuple[CandidateObservation, ...]]
```

Source: `src/crypto_lab/experiments/finalization.py:983`.

Input evidence uses `input_snapshot_evidence` with explicit owner,
payload, expected hash and audit identity.
Generic SYSTEM projections use `stage_core_evidence`.

Sources:
`src/crypto_lab/experiments/finalization.py:1557`,
`src/crypto_lab/experiments/finalization.py:1162`.

### 2.5 Ports, support modules and normative readings

Existing `UnitOfWork` exposes six repository members:
experiments, engine runs, command invocations, retry decisions,
availability observations and diagnostics.

Source: `src/crypto_lab/experiments/ports.py:244`.

Existing clocks, identities and cancellation remain injected.
Source: `src/crypto_lab/domain/ports.py:37`.

**Proposed:**
`experiments/application_ports.py` defines structural application
query/execution/transaction ports and immutable internal values.

It imports no concrete persistence, configuration, process-supervision
or CLI module.
It reaches neither artifacts nor audit.

`cli/execution.py` converts concrete `SupervisionOutcome`
into existing adapter/domain facts.
`experiments/scheduler.py` never imports that concrete outcome type.

Existing outcome shape:
`src/crypto_lab/process_supervision/models.py:604`.

Reuse test support through launch-free helpers and fixture builders.
Production imports no test support.

| Existing support | Source |
|---|---|
| Fixed clock and deterministic experiment doubles | `tests/doubles/experiments.py:596` |
| In-memory UoW | `tests/doubles/experiments.py:1387` |
| Scripted process controller | `tests/doubles/supervision.py:471` |
| Recording observer | `tests/doubles/supervision.py:758` |
| SQLite harness | `tests/persistence_support/harness.py:804` |
| Transaction-counting UoW | `tests/persistence_support/harness.py:1297` |
| Supervised SQLite fixture flow | `tests/persistence_support/supervised.py:281` |
| Finalizing supervised fixture flow | `tests/persistence_support/artifacts.py:2043` |

| Normative reading | Design obligation |
|---|---|
| Specification 7.1 at `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:184` | Registration, compatibility, queue freeze, attempts, finalization and aggregation |
| Specification 7.2 at `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:201` | Local bounded scheduler, original queue order and durable retry delay |
| Specification 8 at `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:209` | CLI composition, inward ports and application dependency direction |
| Specification 22 at `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:1574` | Strict explicit configuration, snapshots and safe catalog bootstrap |
| Specification 22.5 at `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:1651` | Supported local storage, physical confinement and same-volume preflight |
| Specification 24 at `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:1761` | Threat-model limits, bounded parsing, redaction and prohibited controls |
| Specification 25 at `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:1784` | Immutable comparison level; no averaging, voting or promotion |
| Specification 27 at `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:1897` | Package ownership and structural composition boundaries |
| Specification 28 at `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:1960` | Complete test categories and fresh acceptance evidence |
| Specification 29 at `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2154` | Startup, identity-safe recovery, original deadlines and idempotency |
| Specification 30 at `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2200` | Correlation, bounded logging, authoritative audits and diagnostics |
| Specification 33 at `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2305` | All 62 criteria with explicit blocked dispositions |

### 2.6 Guard and documentation reconciliation commitments

These commitments constrain Matrix D and each introducing task.
They do not create additional file bounds.

| Area | Required reconciliation |
|---|---|
| Source census | Nine proposed source additions advance 135 -> 137 -> 138 -> 139 -> 141 -> 144 |
| Root census | T1 adds time/secrets/signal: 30 -> 33; T5 adds sys: 33 -> 34 |
| Runtime imports | Only `cli/runtime.py` gains time/secrets/signal and the additional ctypes edge |
| Execution imports | Only `cli/execution.py` gains the additional asyncio edge |
| Stream import | Only `cli/main.py` gains sys for explicit argv and stream wiring |
| Other roots | No new io/random/msvcrt/logging/tempfile/shutil/subprocess/queue/threading importer |
| `types` | No new importer; preserve strategy/models.py with MappingProxyType only |
| `importlib` | New CLI use is limited to metadata/resources; no discovery or arbitrary import |
| `os` | Preserve artifacts/store.py alone, fstat/fsync only |
| Infrastructure pairs | Add only runtime/time and runtime/secrets: 17 -> 19 |
| Stage 8 pair arithmetic | Persistence pairs plus 1 -> plus 3; preserve named importer confinement |
| Application edges | T3 releases strategy/datasets only; retain concrete infrastructure denials |
| Stage 9 importer sets | Add application.py and scheduler.py to permitted and actual sets in their introducing tasks |
| Reach assertions | Application reaches artifacts/audit; scheduler reaches audit; application_ports reaches neither |
| Persistence port imports | Two existing query modules may import application_ports alongside experiments.ports |
| Persistence direction | T2 creates the exact CLI carve-out and planted experiments control; T5 extends named membership |
| Frozen contracts | Stage 10 itself preserves schemas/hash profiles/actions/tables/migrations; D14 reinspects external corrections |

Sources:
`tests/safety/test_stage3_boundaries.py:197`,
`tests/safety/test_stage3_boundaries.py:459`,
`tests/safety/test_stage5_boundaries.py:148`,
`tests/safety/test_stage7_boundaries.py:147`,
`tests/safety/test_stage8_boundaries.py:881`,
`tests/safety/test_stage8_boundaries.py:940`,
`tests/safety/test_stage9_boundaries.py:153`,
`tests/safety/test_stage9_boundaries.py:549`.

**Ambient-clock exemption, owned by T1.**

Extend `_ambient_clock_violations` with a label-keyed constant:

```text
_AMBIENT_CLOCK_EXEMPTIONS ==
frozenset({("cli/runtime.py", "datetime.datetime.now")})
```

The tree-wide ambient-clock test consults that exemption.
The environment scan remains unchanged.

Sources:
`tests/safety/test_stage5_boundaries.py:233`,
`tests/safety/test_stage5_boundaries.py:425`.

Add the exact selector:

`tests/safety/test_stage5_boundaries.py::test_each_ambient_clock_exemption_licenses_exactly_its_pair`

Mirror the existing whole-block, pair-by-pair discipline:

- The exempted module must really perform its licensed read.
- `datetime.datetime.utcnow` still fails in `cli/runtime.py`.
- `datetime.date.today` still fails there.
- `datetime.datetime.now` still fails in sibling `cli/main.py`.
- The same read still fails in a planted `cli/probe.py`.
- Aliased spellings resolve to the same pass/fail decisions.
- Import-time draws still fail the fresh-import probe.
- No environment access follows from the clock exemption.

Preserve the existing clock-shape and injected-clock controls.

Sources:
`tests/safety/test_stage5_boundaries.py:575`,
`tests/safety/test_stage5_boundaries.py:654`,
`tests/safety/test_stage5_boundaries.py:658`.

**Persistence-direction release, owned by T2.**

The existing Stage 8 loop denies persistence imports
from every source module outside persistence.

Source: `tests/safety/test_stage8_boundaries.py:940`.

Carve out exactly the CLI package's named concrete composition importers:

- T2: `cli/startup.py`.
- T5: `cli/composition.py`.
- T4/T5: `cli/execution.py` only if its reviewed implementation imports persistence.

Keep exact importer membership synchronized with actual imports.
Do not authorize unused entries or every future CLI module.

Every other package stays denied.
Add a planted `experiments/probe.py` persistence import that still fails.
Application services, scheduler and application ports remain denied.

This implements the specification's CLI -> Persistence direction.

Source:
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:215`.

**Released-edge controls, owned by T3.**

Releasing strategy/datasets must also update the planted controls
that currently use those packages as forbidden examples.

Re-point the architecture control and both Stage 5 parametrized controls
to `crypto_lab.process_supervision`.
D06 keeps that package outside the application allowlist.

Sources:
`tests/architecture/test_package_import_boundaries.py:698`,
`tests/safety/test_stage5_boundaries.py:148`.

**Census mirror discipline.**

Reconcile all nine census owners:

| Owner | Existing source pin |
|---|---|
| Stage 3 source/root inventories | `tests/safety/test_stage3_boundaries.py:432` |
| Dotted package inventory | `tests/unit/test_package_layout.py:12` |
| Stage 8 source and complete equalities | `tests/safety/test_stage8_boundaries.py:1067` |
| Stage 9 source arithmetic and roots | `tests/safety/test_stage9_boundaries.py:587` |
| SQLite database cross-pins | `tests/unit/persistence/test_sqlite_database.py:1809` |
| SQLite migration cross-pins | `tests/unit/persistence/test_sqlite_migrations.py:1072` |
| Supervisor preflight cross-pins | `tests/unit/process_supervision/test_supervisor_preflight.py:1246` |
| Restart cross-pins | `tests/unit/process_supervision/test_restart_reconciliation.py:1760` |
| Artifact-store cross-pins | `tests/unit/artifacts/test_artifact_store.py:2047` |

Advance quoted source-text mirrors together with the literals they inspect.
Preserve negative historical pins.
Append new dotted names outside every pinned historical positional slice.

Matrix D lists the individual assertions and task-specific arithmetic.

**Task 8 documentation guards.**

| Guard source | Required coherent treatment |
|---|---|
| `tests/safety/test_stage3_boundaries.py:1132` | Preserve README Local setup heading, commands and prose verbatim; operational examples belong elsewhere |
| `tests/safety/test_stage3_boundaries.py:1865` | Reconcile exact roadmap/README/guide status and historical-hash rules |
| `tests/safety/test_stage3_boundaries.py:1659` | Preserve `_VERIFICATION_STAGE9_OBLIGATIONS`; append new closure evidence outside its pinned passage |
| `tests/safety/test_stage5_boundaries.py:536` | Advance approved-block subtraction before new Stage 10 prose; preserve Stage 11 containment |
| `tests/safety/test_stage7_boundaries.py:777` | Replace the start denial only with exact evidenced status; preserve documentation restrictions |
| `tests/safety/test_stage8_boundaries.py:637` | Reconcile later-stage claim denials through exact state-aware pins |
| `tests/safety/test_stage8_boundaries.py:1138` | Replace README not-started sentence with Stage 9's twin assertion |
| `tests/safety/test_stage8_boundaries.py:1139` | Replace guide not-started sentence with Stage 9's twin assertion; preserve Stage 9 not-started denials |
| `tests/safety/test_stage9_boundaries.py:731` | Reconcile `_STAGE10_DEFERRED_ROW`, active status and forward clauses |
| `tests/safety/test_stage9_boundaries.py:780` | Preserve six historical focused commands and byte-pinned Stage 9 obligations |
| `tests/safety/test_gitnexus_development_tooling.py:371` | Advance approved-plan sentence only after actual plan acceptance; preserve disabled outcome |

No guard is weakened to admit premature completion.
T8 performs the roadmap Planned -> Approved wording reconciliation
and the GitNexus approved-plan sentence reconciliation.
The approval commit itself remains plan-only.

---

## 3. Matrix A: CLI commands, typed inputs, configuration precedence, identities, outputs and exit behaviour

### 3.1 Closed invocation contract

Everything in this section is proposed.
The existing parser implements version/help only.

Source: `src/crypto_lab/cli/main.py:12`.

T5 implements grammar, concrete composition and reporting.
T6/T7 demonstrate behavior through the test routes in section 7.

No command accepts Python code, a module name, shell text,
environment entries, executable override, raw attempt token
or destination URL.

Every operational command requires:

```text
--invocation-base ABS_LOCAL_DIRECTORY
--correlation-id CorrelationId
```

Optional common flags are:

```text
--config ABS_TOML
--local-override ABS_TOML
--output {text,json}
```

Default output is `text`.
Reject duplicate singleton flags, unknown flags,
surplus positionals and malformed values.

The invocation base is explicit.
Never call cwd/home/expanduser to invent it.
Apply P1's absolute drive-letter path admission to path-valued CLI tokens.

`text` and `json` project the same sanitized structured facts.
JSON emits one bounded result document.
Diagnostics go to stderr with stable code, message,
corrective category, retriable flag and local references.

Neither mode dumps source documents, raw streams or mutable exceptions.

Help/version require no operational flags
and construct no runtime services.

Unknown-option echo is narrowly defined:

"Echo an unknown option only when it matches the closed safe pattern
`^--?[A-Za-z0-9][A-Za-z0-9-]{0,63}$`;
otherwise print a bounded placeholder with the token count."

Preserve `SystemExit(2)` and the existing
`unrecognized arguments: --unknown` regression.

Source: `tests/unit/test_cli.py:68`.

T5 adds the unit nonmatching control.
T6 adds its separately named production-parser integration control.
Path-like, equals-bearing, overlength and control-character inputs
must not reach stderr verbatim.

Apply equivalent bounded handling to other parser errors
that could echo supplied values.

### 3.2 Typed configuration overrides

Only existing `CliOverrides` fields receive CLI spellings.
Omitted flags mean no override.
Validate the complete merged configuration after scalar conversion.

Source: `src/crypto_lab/configuration/models.py:545`.

| Option | Typed validation / treatment |
|---|---|
| `--runtime-root` | Existing PathText; absolute local drive-letter CLI path |
| `--data-root` | Existing PathText; absolute local drive-letter CLI path |
| `--artifacts-root` | Existing PathText; absolute local drive-letter CLI path |
| `--logs-root` | Existing PathText; absolute local drive-letter CLI path |
| `--runtimes-root` | Existing PathText; absolute local drive-letter CLI path |
| `--max-concurrent-runs` | Strict integer 1..8; operational and audited |
| `--maximum-attempts-per-slot` | Strict integer 1..5; material; initial attempt counts |
| `--automatically-retry-terminal-states` | One comma-separated value, including explicit empty; unique subset FAILED/TIMED_OUT/UNAVAILABLE in existing normalized order |
| `--retry-delay-seconds` | Strict integer 0..300; material |
| `--heartbeat-interval-seconds` | Strict integer 1..300 |
| `--missing-heartbeat-seconds` | Strict integer 2..900; at least twice heartbeat interval |
| `--describe-timeout-seconds` | Strict integer 1..300 |
| `--validate-timeout-seconds` | Strict integer 1..1800 |
| `--default-run-timeout-seconds` | Strict integer 1..604800 |
| `--finalization-timeout-seconds` | Strict integer 1..3600 |
| `--cancellation-grace-seconds` | Strict integer 0..300 |

Absolute CLI root overrides do not change relative TOML-root resolution.
TOML roots retain the existing primary-parent/explicit-base rule.

Integers reject booleans, fractional syntax
and conversion through floating point.

There are no CLI overrides for policy, credentials, catalog executables,
database filename, protocol ceilings, retained-file count or stderr budget.

After queueing, material settings come from the frozen experiment snapshot.
A conflicting invocation override refuses;
it never mutates frozen material.

Sources:
`src/crypto_lab/configuration/models.py:545`,
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:1591`.

### 3.3 Command matrix

**C** means the explicit precedence/base contract.
**I** means current-database/integrity gates.
**R** means exclusive startup reconciliation before dispatch.

Read projections never recover or launch children.
Every file input is explicitly named, bounded, strictly parsed
and physically confined by T5's concrete reader.

B2 applies to required mutation facts, including preparatory commands.
B3 applies to correlated creation and original durable queue-order facts.
The success rows below describe the post-prerequisite contract.
They do not authorize unsupported mutation on the planning base.

| Command / sub-command | Typed inputs and validation | Configuration, identities and tokens | Output / exit | Criterion; owner |
|---|---|---|---|---|
| No arguments; `--help`; command `--help` | Closed argparse grammar | No C/I/R, identity draw or token | Help stdout; empty stderr; 0 | 33.1/1, 33.7/1; T5 |
| `--version` | Existing installed-version behavior | No operational composition | Exact installed version stdout; 0 | 33.1/1; T5 |
| Invalid grammar / unknown option | Safe-option echo rule; bounded placeholder/count otherwise | No runtime mutation | Bounded usage diagnostic; 2 | 33.2/2, 33.7/1; T5,T6 |
| `config check` | C; complete ApplicationConfig validation | Compute existing snapshots/hashes; no experiment/run/token | Safe hash/configuration summary; 0 or input refusal | 33.2/2,6, 33.7/2; T3,T5 |
| `database init` | C; safe configured filename; explicitly absent target | Exclusive maintenance route; no token; required audit B2-gated | Current revision or stable refusal; no overwrite | 33.2/9, 33.5/6; T2,T5 |
| `database migrate` | Existing EMPTY/BEHIND database; preserve existing revision classifications | C; exclusive maintenance; B2-gated required audit | Applied revision or current-state replay; no downgrade | 33.2/9, 33.5/6; T2,T5 |
| `database check` | Existing database only | C+I; no migration/reconciliation/token | Revision and integrity facts; query 0 if checks pass | 33.5/6,8,10; T2,T5 |
| `runtime reconcile` | Current database; no force/adopt/reset flag | C+I+R; fresh supervisor identity; existing surviving-token lookup only | Recovery summary; unresolved work fenced; B2-dependent mutations refuse | 33.4/6-8,12, 33.5/8; T2,T5,T7 |
| `strategy register` | `--source ABS_YAML`, `--source-name SourceName`; safe bounded YAML | C+I+R; existing content identity; no run/token; B2 | Version/hash, replay or conflict after prerequisites | 33.2/6, 33.3/1-2, 33.6/7; T3,T5 |
| `dataset register` | `--descriptor ABS_JSON`, `--partitions ABS_JSON`; strict descriptor/partition tuple; identity agreement | C+I+R; confined fixture files; no acquisition/normalization; B2 | Dataset hash/provenance and registration result | 33.6/1,7, 33.7/3; T3,T5,T6 |
| `adapter list` | No selector/discovery directory | C; explicit catalog and D02 metadata; no process/run/token | Ordered registered identities/hashes; 0 or configuration refusal | 33.1/5, 33.7/4; T3,T5 |
| `adapter describe` | `--adapter-name NormalizedIdentifier`, `--adapter-version SemanticVersion` | C+I+R; DESCRIBE invocation/observation IDs; no run/token; B2 | Negotiation/availability and ADAPTER evidence; unavailable distinct | 33.3/6, 33.4/1-3, 33.6/7; T3-T6 |
| `experiment create` | `--draft ABS_JSON`; existing ExperimentSpecDraft, selected slots, hashes, Decimal assumptions and retry policy | C+I+R; correlated lookup before new identity; B2/B3 | DRAFT identity/hash, identical replay or conflict | 33.2/5-8, 33.5/2; T3,T5,T6 |
| `experiment validate` | `--experiment-id ExperimentId`, `--expected-revision NONNEG_INT`; stored hashes | C+I+R; explicit descriptor/compatibility facts; no run token; B2 | VALIDATED/material diagnostics; incompatibility/unavailability distinct | 33.3/4-6,8; T3,T5,T6 |
| `experiment queue` | ID/revision; exact retry/material hashes and compatibility agreement | C+I+R; snapshot, QUEUED-CAS instant and audit atomic; B2/B3; no token | QUEUED identity/hash or replay/conflict; frozen inputs unchanged | 33.2/8, 33.5/2; T3,T5,T6 |
| `experiment run` | ID/revision; validate/queue eligible draft or verify queued selection | C+I+R; frozen settings, ordered CAS claims; fresh material only for eligible new attempts; B2/B3 | Terminal aggregate, every slot outcome and separate result/evidence refs | 33.1/4-6, 33.3/6, 33.4/1-11, 33.5/1-5; T3-T6 |
| `experiment resume` | `--experiment-id ExperimentId`; resumable durable state or terminal replay | C+I+R; original deadlines/counts/not-before; no token reconstruction; B2/B3 where mutations are required | Recovered/terminal aggregate; new token only for approved new attempt | 33.4/7-8, 33.5/3-5,8; T2,T4-T7 |
| `experiment cancel` | ID/revision and global correlation | C+I; bounded control CAS; no recovery/launch; required cancellation audit B2-gated | Accepted request/replay 0; cleanup pending until observed complete | 33.4/6,10, 33.5/1,4; T4-T7 |
| `experiment status` | `--experiment-id ExperimentId` | C+I; read-only; no new material | Durable experiment/slot/attempt/invocation facts; query 0 even for failed state | 33.3/6, 33.6/10; T5,T6 |
| `experiment evidence` | Experiment ID; optional `--run-id RunId` belonging to it | C+I; read-only hashes/audits/lineage | Bounded document; RESULT/EVIDENCE separate; query 0 | 33.4/11, 33.6/3-7,10-11; T5-T7 |
| `comparison evaluate` | `--left-run-id RunId`, `--right-run-id RunId`, `--level {LEVEL_1,LEVEL_2,LEVEL_3}` | C+I; existing registered core manifests; no new run/token | Eligibility/reasons; 0 eligible/differences; 5 ineligible | 33.3/7, 33.6/4; T5,T6 |
| `retention purge-quarantine` | `--entry-id` for one stored entry; no path/pattern/all flag | C+I+R; existing audited purge; active-journal refusal | Deletion/replay evidence or refusal; finalized refs preserved | 33.5/10, 33.6/6,11; T5-T7 |

Database initialization/migration use their dedicated maintenance route.
An absent or behind database cannot pass ordinary startup.

The existing normal opener refuses creation.
`apply_migrations` accepts EMPTY/BEHIND, not CURRENT.
Implement current-state replay before invoking it.

Sources:
`src/crypto_lab/persistence/migration_runner.py:227`,
`src/crypto_lab/persistence/migration_runner.py:318`.

Selected slots retain their typed logical-slot identities on replay.
Attempt creation returns raw transient token material only for a new attempt.
Never regenerate a missing token for an existing attempt.

Sources:
`src/crypto_lab/domain/experiment.py:129`,
`src/crypto_lab/experiments/run_service.py:103`.

### 3.4 Outcome projection and CLI exit codes

CLI exits are reporting decisions.
They are separate from the adapter's eight process-exit categories.
Persist captured adapter exits/categories unchanged.

Source: `src/crypto_lab/adapters/exit_codes.py:18`.

| CLI exit | Meaning and projection |
|---|---|
| 0 | Successful command/query; COMPLETED or COMPLETED_WITH_WARNINGS; accepted cancellation request; structured warnings retained |
| 1 | Core invariant, artifact-integrity or unexpected internal failure; safe diagnostic and available authoritative summary |
| 2 | Grammar, typed-input or configuration refusal; empty result stdout and bounded stderr diagnostic |
| 3 | Revision/idempotency conflict or dispatch contention; no overwrite/adoption |
| 4 | Database/storage/migration/startup-recovery or unavailable-required-audit refusal; no prohibited mutation/launch |
| 5 | No applicable engine or comparison ineligibility; explicit reasons |
| 6 | Required runtime unavailable without a successful aggregate |
| 7 | Engine crash or semantic execution failure; captured process facts preserved |
| 8 | Protocol/security refusal; no raw stream or exception dump |
| 9 | Core command/run/finalization deadline winner; original deadline and scope |
| 130 | Driving command cancelled by user/durable cancellation; final observed state after bounded cleanup handling |

An unavailable required audit capability is a core prerequisite refusal,
not an engine failure.
Expose its stable corrective category and blocked operation.
Do not fabricate an authoritative audit for the refusal.

Existing aggregation chooses aggregate state.
CLI arithmetic never replaces it.
COMPLETED_WITH_WARNINGS remains exit 0 with every non-success slot visible.

For FAILED aggregates, choose the diagnostic category deterministically:
core invariant, security/protocol, artifact integrity,
timeout, engine, unavailable, then not-applicable.
Break ties by slot ordinal and diagnostic ID.

Successful status/evidence queries return query exit 0
independently of the queried execution's failure.

Source: `src/crypto_lab/experiments/aggregation.py:385`.

### 3.5 Redaction, replay and acceptance boundaries

Retain raw attempt material only in existing temporary carriers
and the permitted invocation-scoped request-material lifetime.

Use per-invocation lifecycle instances where necessary.
Discard each instance after command conclusion and bounded cleanup.
The existing lifecycle stores registered material in its instance map.

Sources:
`src/crypto_lab/experiments/supervision_lifecycle.py:352`,
`src/crypto_lab/experiments/supervision_lifecycle.py:354`.

Projections contain no raw token, untrusted stdout,
original adapter-result control bytes, configuration source text
or mutable exception dump.

Unknown-option errors use section 3.1's safe-pattern rule.
The harmless `--unknown` regression remains green.
Unsafe supplied values are replaced with bounded placeholder/count output.

JSON/text share sanitized facts.
Hashes remain labelled hashes.
An evidence reference is never presented as a research result.

Operational replay uses durable identities and CAS:
prior identical outcome or stable conflict, never a silent duplicate.
B3 proof must survive process restart.
An in-memory cache is insufficient.

T6/T7 independently scan exact raw-token bytes after relevant cleanup/recovery,
before fixture teardown, including a conformant token-bearing VALIDATE row.
They observe matching survivors before any cleanup helper terminates them.

Schema generation/checks, synchronization, builds and full-suite execution
remain development/verification operations.
They are not additional product commands.

P1's `cli-local` remains operator-run after hook re-pinning.
Tests never invoke that profile.

B1/B2 and unresolved B3 acceptance cells remain blocked
regardless of other command passes.
Neither this matrix nor a command result constitutes Project 1 acceptance.

## 4. Matrix B: startup steps, lease ownership, integrity gates and restart actions

### 4.1 Reading rules and ownership

All new functions, ports and selectors below are proposed.
Their implementation and execution remain UNVERIFIED.

Matrix B applies to Matrix A's integrity and reconciliation routes:

- Help/version construct no operational services.
- Configuration and catalog projections need no database.
- Status, evidence and comparison queries do not reconcile or launch.
- Cancellation uses the bounded durable control route.
- Initialization and migration use exclusive maintenance ownership.
- A driving command completes the reconciliation barrier before scheduling.

The normative startup order is specification 29.2.

Source:
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2154`.

Configuration precedence and supported storage remain governed by specification 22.

Sources:
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:1576`,
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:1651`.

The existing artifact recovery entry point requires caller-held reconciliation
exclusion and prohibits scheduling before that phase completes.

Source: `src/crypto_lab/artifacts/recovery.py:1422`.

In this matrix:

- R means refuse the driving operation.
- C means reconcile using durable authority, CAS and purpose-specific validation.
- D means report a degraded capability without bypassing an integrity gate.

A deferred lease or unresolved child fences its affected work.
It never grants permission to relaunch that work.

Dispatch ownership spans startup and local driving.
The nested reconciliation phase ends before scheduling begins.
A competing dispatcher receives a stable contention result.

Cancellation may perform its bounded durable CAS while the dispatcher owns
the database. It neither reconciles nor launches behind that owner.

Required audits are fact obligations.
They do not name invented `AuditAction` members.

B2 is checked before the associated unsupported mutation or child launch.
A structured log or refusal projection cannot substitute for that audit.

### 4.2 Ordered startup matrix

The criterion and task columns identify contributions to the complete behavior.
Section 7.4 is the authoritative criterion-to-task assignment.
Its inverse fixes the criteria lists used by section 8.

| ID / order | Owner and interface | Gate and ownership | Failure and restart treatment | Required observable fact | Criteria; tasks |
|---|---|---|---|---|---|
| B01 Parse | `cli/main.py::main`; `cli/commands.py::parse_command` | Closed Matrix A grammar; explicit base/correlation; safe unknown-option echo | R: exit 2 before runtime mutation; parse again after restart | Bounded input-refusal projection | 33.2/2, 33.7/1; T5 |
| B02 Configuration | `cli/composition.py::load_inputs`; existing loader | Exact precedence; strict merged configuration; fixed safety policy | R: invalid input/policy/base, exit 2; reload only explicit sources | Safe selection/hash facts; required mutation audit remains B2-gated | 33.2/2,6,8; T3,T5 |
| B03 Snapshot | `cli/composition.py::load_inputs`; existing snapshot functions | Complete audit snapshot and material projection remain distinct | R: inconsistent projection/hash; queued material remains authoritative on restart | Selected hashes; concurrency/retention audit requires B2 | 33.2/6,8, 33.6/11; T3,T5 |
| B04 Runtime construction | `cli/runtime.py::create_runtime_services` | Call-time UTC/monotonic clock, UUID4 identity source and cancellation | R: unavailable required facility; restart draws a new supervisor identity only | Runtime capability result without token or entropy bytes | 33.2/4-5, 33.7/1; T1 |
| B05 Storage probes | `cli/runtime.py::probe_storage`; `cli/startup.py::check_storage` | Explicit absolute local roots; fixed NTFS; physical identity; same staging/artifact volume; path ceilings | R: unsafe or unsupported roots, exit 4; reprobe original roots without redirection | Stable storage diagnostic and supported-path facts | 33.4/12, 33.6/1, 33.7/3; T1,T2 |
| B06 Database opening | `cli/startup.py::open_current_database`; existing normal opener | Existing application database; configured filename and bounded busy timeout | R: absent, foreign, unreadable or unavailable database, exit 4; reopen through the same route | Safe database-open result | 33.2/9, 33.5/6; T2,T5 |
| B07 Revision/integrity | `cli/startup.py::check_database`; existing revision and consistency checks | CURRENT revision; execute every integrity query; classify all twelve consistency fields | R: corruption, read failure or contradictory authority; recoverable `journal_open`/`unmapped_finalizing` enter fenced inventory; recheck after recovery | Revision, complete counts and classification; no row dump | 33.2/9, 33.5/6,9-10; T2 |
| B08 Schema distribution | `cli/startup.py::check_schema_distribution` | Exact registry bytes against `schemas/` derived from explicit `--invocation-base`; section 4.4 fixes selection | R: absent, extra, changed or unsafe schema entry, exit 4; never generate replacements | Selected location class, registry count and bounded mismatch codes | 33.2/1,6-7; T2,T8 |
| B09 Dispatch exclusion | `cli/runtime.py::acquire_dispatch_owner`; `cli/startup.py::begin_reconciliation` | Named Windows mutex keyed by canonical database identity; fresh authority after acquisition | R: contention, exit 3; abandoned ownership requires complete reconciliation | Acquired/contended/abandoned observation; no PID-only authority | 33.4/12, 33.5/8; T1,T2,T7 |
| B10 Resource opening | `cli/composition.py::open_resources`; existing store/log openers | Probes and applicable ownership passed; explicit log bounds; required audit capability admitted before its mutation | R: unavailable required resource; D only for an explicitly optional projection failure; reopen and reconcile partial layout | Resource-open result; authoritative audit failure never becomes D | 33.6/2,11; T2,T5 |
| B11 Durable inventory | `cli/startup.py::inventory_work`; typed persistence queries | Experiments, slots, attempts, invocations and journals agree; detached complete projections | R: unreadable or contradictory facts; retain bytes; reload through fresh connections | Counts and stable inconsistency diagnostics | 33.5/8-10; T2,T7 |
| B12 Journal/candidate inventory | `cli/startup.py::reconcile_startup`; `reconcile_finalization(..., phase="inventory")` | Purpose/owner classification; protect active leases, registered mappings and unresolved RESULT work | C: safe preliminary classification/quarantine only; no RESULT promotion or orphan sweep; R on authoritative read failure | Supported quarantine facts and explicitly deferred counts | 33.5/8,10, 33.6/2-3; T2,T7 |
| B13 Invocation reconciliation | `cli/startup.py::reconcile_startup`; existing invocation reconciler | Every nonterminal invocation and terminal incomplete cleanup; creation/executable identity checked | C: verified cleanup/enrichment; unresolved targets fenced; original deadlines retained; B2 refuses unsupported required transitions | Process identity, cleanup and lifecycle facts | 33.4/6-8,10,12, 33.5/8; T2,T7 |
| B14 Related runs | `cli/startup.py::reconcile_runs`; application ports | Invocation/run coupling, latest-attempt agreement and terminal winners | C: only permitted audited transitions; reread CAS winner; lost exit alone cannot imply success or PROTOCOL_FAILED | Causal run-reconciliation diagnostic and durable winner | 33.4/6-8, 33.5/1,8-9; T2,T4,T7 |
| B15 Purpose recovery | `cli/startup.py::reconcile_startup`; `reconcile_finalization(..., phase="recover")` | Every 29.3 RESULT gate; independent 29.4 EVIDENCE gates; fresh child/lease authority | C: eligible recovery or quarantine/corruption; preserve unexpired leases; never reconstruct tokens or extend deadlines | Existing finalization actions and phase-labelled counts | 33.4/8-11, 33.6/2-9; T2,T7 |
| B16 Requeue assessment | `experiments/scheduler.py::recover_queue`; query/execution ports | Proven prelaunch work or approved new attempt; original queue instant, attempt count and retry-not-before | C: assess eligibility without launching; fence absent/contradictory facts; B2/B3 gates remain | Faithful requeue/retry decision and observation facts | 33.5/3-5,8; T4,T7 |
| B17 Orphan sweep | `cli/startup.py::reconcile_startup`; `reconcile_finalization(..., phase="sweep")` | Protect active leases and finalized refs; quarantine orphan roots and unregistered content | C: confined cleanup after recovery/requeue assessment; D: overdue retained quarantine; unreadable unsafe work remains fenced | Supported orphan/quarantine/overdue facts and phase summary | 33.5/8,10, 33.6/5-6,11; T2,T7 |
| B18 Scheduling barrier | `cli/startup.py::permit_scheduling`; `experiments/scheduler.py::drive` | All required phases passed; affected unresolved work fenced; reconciliation phase released; dispatch owner retained | R: failed prerequisite means zero new launches; rebuild permit from fresh facts after restart | Complete reconciliation result and dispatch-permitted projection | 33.1/4,6, 33.5/8; T2,T4,T7 |
| B19 Close/release | `cli/composition.py::close`; `cli/runtime.py::release_dispatch_owner` | Bounded cleanup observed; resources disposed; owner handle closed in `finally` | Report incomplete cleanup accurately; kernel release permits later recovery; durable cleanup targets remain | Final observed state, cleanup result and ownership release | 33.4/6,12, 33.5/8; T1,T5,T7 |

The existing revision classifications are exactly:

`EMPTY`, `CURRENT`, `BEHIND`, `UNKNOWN`, `UNVERSIONED`.

Source: `src/crypto_lab/persistence/migration_runner.py:107`.

Normal opening refuses an absent database and admits CURRENT only.

Source: `src/crypto_lab/persistence/migration_runner.py:227`.

The maintenance opener admits EMPTY, BEHIND and CURRENT.
`apply_migrations` itself accepts EMPTY/BEHIND.
T2/T5 implement CURRENT replay before calling that function.

Sources:
`src/crypto_lab/persistence/migration_runner.py:254`,
`src/crypto_lab/persistence/migration_runner.py:318`.

Do not add invented AHEAD or DIVERGENT classifications.

**B07 consistency treatment.**

Preserve the twelve existing fields and execute every query.

Source: `src/crypto_lab/persistence/database.py:357`.

The consistency implementation raises on query failure rather than returning
a clean count.

Source: `src/crypto_lab/persistence/database.py:657`.

Treat these findings as follows:

- The eight original consistency findings refuse dispatch when nonzero.
- `refs_without_manifest_file` and `success_without_manifest` refuse dispatch.
- `unmapped_finalizing` and `journal_open` require classified, fenced recovery
  inventory rather than an unconditional refusal before B12.
- Recheck consistency after recovery.
- An open valid lease may remain deferred only with its affected work fenced.
- Missing rows, failed reads or contradictory ownership cannot become empty success.

The last two counts are not ignored.
Their recovery treatment follows the startup order rather than preventing it.

### 4.3 Artifact phase reconciliation and preserved interfaces

The existing complete pass runs:

1. Open-journal recovery.
2. Recoverable-candidate reconciliation.
3. Orphan-root quarantine and raw-root closure.
4. Unregistered-content quarantine.
5. Overdue-quarantine reporting.
6. The summary audit.

Source: `src/crypto_lab/artifacts/recovery.py:411`.

That combined pass cannot establish D07's ordering merely by being called twice
around process reconciliation.

T2 adds one optional keyword-only internal `phase` selector to the public
`reconcile_finalization` entry point.

The closed selected values are:

```text
inventory
recover
sweep
```

Omission preserves the existing complete pass.

This selector is a call-time composition interface.
It adds no CLI flag, canonical field, configuration field, table or migration.

| Selection | Required behavior |
|---|---|
| Omitted | Preserve the complete pass, original report semantics and original summary-detail set |
| `inventory` | Classify journals/candidates and perform safe preliminary reconciliation; protect active leases, registered mappings and unresolved RESULT bytes; no RESULT promotion or orphan sweep |
| `recover` | Reread durable authority after invocation/run reconciliation; resume only eligible purpose-specific work |
| `sweep` | Perform orphan-root/content cleanup and overdue reporting after recovery and requeue assessment |
| Anything else | Refuse before work; no permissive fallback |

The existing report is a frozen dataclass with eight count fields.

Source: `src/crypto_lab/artifacts/recovery.py:214`.

A selected phase returns that same report type with unchanged count meanings.
Its summary uses the existing
`RECONCILIATION_FINALIZATION_RESUMED` action and adds exactly one bounded detail
key, `phase`, identifying the selected value.

The omitted-selector pass retains its existing detail set without that key.

The existing summary action and count details are at
`src/crypto_lab/artifacts/recovery.py:1305`.

Its transaction-bound append is at
`src/crypto_lab/artifacts/recovery.py:1323`.

Pin both detail shapes in the artifact-recovery tests.
A phase summary cannot be presented as a complete-pass result.
Do not add phase counts together and infer unique substantive changes.

Each phase obtains fresh authority.
A transient inventory cannot replace a lease revision, registered mapping,
captured exit or child-identity check.

An unexpired journal remains deferred after a new CLI acquires dispatch ownership.
Restart alone supplies no journal-takeover authority.

Sources:
`src/crypto_lab/artifacts/recovery.py:5`,
`src/crypto_lab/artifacts/recovery.py:451`.

Preserve its bytes and fence affected work.
Expired takeover still uses the existing audited CAS.

RESULT recovery requires every specification 29.3 gate.

Source:
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2173`.

EVIDENCE recovery remains independent and cannot promote success,
reopen a run or create a `RunManifest`.

Source:
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2186`.

Disk, lock, permission, checksum and move failures retain their distinct
RESULT/EVIDENCE consequences.

Source:
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2192`.

### 4.4 Schema selection, audit and failure boundaries

**Schema-location selection is explicit.**

For the operational source-tree route in this plan:

1. T5's `cli/composition.py::load_inputs` receives Matrix A's explicit
   `--invocation-base`.
2. It derives exactly `invocation_base / "schemas"`.
3. It passes that selected source schema root to
   `cli/startup.py::check_schema_distribution`.
4. T2 compares the complete selected tree with registry-rendered bytes,
   rejecting missing, extra, altered or physically unsafe entries.

There is no schema-location CLI option, configuration extension,
cwd fallback, profile lookup, `sys.path` search or arbitrary directory discovery.

An invocation base without the required source schema tree refuses this route.
Tests supply an explicit base with the required tree.

This resolves source-mode selection without assuming that an editable
installation contains `crypto_lab/schemas`.

The observed packaging uses `dev-mode-dirs = ["src"]` and wheel force-inclusion
from `schemas` to `crypto_lab/schemas`.

Sources: `pyproject.toml:40`, `pyproject.toml:42`.

Wheel/sdist membership and byte checks remain the operator verifier's
distribution responsibility. They do not choose the product startup root.

Sources:
`scripts/verify_schema_distribution.py:21`,
`scripts/verify_schema_distribution.py:35`.

T8 preserves that distinction in the runbook.
Startup neither builds archives nor imports the verification script.

| Failure | Disposition |
|---|---|
| Invalid grammar, configuration or safety policy | Refuse before mutation; exit 2 |
| Required schema/distribution or storage gate fails | Refuse dispatch; exit 4 |
| Corrupt, unreadable or contradictory durable authority | Preserve bytes; refuse dispatch; exit 4 |
| Ownership contention | Exit 3; no recovery, adoption or launch |
| Recoverable journal/candidate/process state | Reconcile under ownership with fresh CAS/identity authority |
| Active lease or unresolved child identity | Fence affected work; report pending recovery |
| Overdue retained quarantine or optional projection failure | Report degraded capability; preserve authoritative terminal outcome |
| Unsupported required application audit | B2 refusal before its mutation/launch; exit 4 |
| Required supported audit append fails | Roll back the associated mutation; do not downgrade to a log warning |
| Core invariant or artifact-integrity failure | Safe diagnostic; no success projection; exit 1 |

The current audit vocabulary is closed and lacks the full application fact set.

Source: `src/crypto_lab/audit/models.py:61`.

Configuration selection, migration, process reconciliation and application
transitions therefore need the same B2 capability admission as dispatch.
Do not complete an unsupported mutation and defer only its audit assertion.

---

## 5. Matrix C: workflows, outcomes, attempts, manifests, evidence, retry and cancellation

### 5.1 Shared workflow contract and execution route

Everything in Matrix C specifies proposed evidence.
Every runtime result remains UNVERIFIED.

W/X rows invoke production `crypto_lab.cli.main.main(argv)` in-process,
with scoped output capture or injected streams.
They use production composition, SQLite, the supervisor, finalizer and registrar.

They do not import an existing test module as a support library.

Real CLI children use the test interpreter selected by the reviewed launcher:

```text
sys.executable -I -B -m crypto_lab.cli <closed Matrix A arguments>
```

Only these two existing subprocess-importer modules host selectors that need
such a child:

- `tests/unit/test_cli.py`.
- `tests/integration/artifacts/test_finalization_crash_child.py`.

Those modules call launch-free helpers in `tests/cli_support.py`.
The helpers never call back into either test module.
New W/X/R/support modules do not import `subprocess`.

The existing importer allowlist names both modules.

Source: `tests/safety/test_stage6_boundaries.py:106`.

Its equality and cardinality remain thirteen.

Source: `tests/safety/test_stage6_boundaries.py:372`.

Tests never invoke `cli-local`.
P1's operational `cli-local` demonstration is operator-run.

The normal complete setup is:

```text
database init
-> strategy/dataset registration
-> experiment create
-> experiment validate
-> experiment queue
-> experiment run
```

Each command supplies Matrix A's explicit base/configuration/correlation inputs.
A recovery row identifies its durable prestate and how it was established.
A planted prestate does not prove that the blocked setup commands succeeded.

**Per-row B2 rule.**

On this planning base, full workflows requiring unsupported application
audit facts are blocked before the corresponding mutation or launch.

For those rows:

- The stated outcome is the required post-prerequisite oracle.
- The successful workflow selector/facet is authored at D14 reinspection.
- Current dispatch tests the stable refusal and absence of prohibited mutation.
- An audit assertion is never merely deferred while its mutation proceeds.

No row selects "audit assertion deferred, mutation proceeds" for an unsupported
required fact.

All full workflow selectors marked `B2: blocked` carry this tag:

`(B2-gated: authored at the D14 reinspection after integration; not part of this dispatch)`

Where creation replay, original queue order or durable requeue proof is required,
the row also carries:

`(B3-gated: authored at the D14 reinspection after integration; not part of this dispatch)`

The marker column below applies to the entire full-workflow selector unless
a narrower, independently supported facet is explicitly identified.

An existing artifact-only operation may proceed with its supported actions
when it requires no preceding unsupported application mutation.
That narrow proof does not close a blocked complete CLI workflow.

**Retry and artifact notation.**

R6 means all six existing retry gates, hard blocks, cancellation races,
fresh-observation requirements and the 1..5 total-attempt maximum.

A successor receives fresh run/invocation identities, token material and roots.
Restart reuses the durable retry-not-before instant.

Sources:
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:207`,
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2361`.

F means the production RESULT pipeline and core manifest.
E means independently eligible sanitized core EVIDENCE.
N means no RESULT reference, RESULT run link or core `RunManifest`.

N permits independently valid EVIDENCE and historical input snapshots.
A candidate row alone is not finalization.

The existing conclusion registers RUN declarations before deciding
RESULT eligibility.

Source: `src/crypto_lab/experiments/finalization.py:3745`.

### 5.2 Workflow matrix

The output/state columns are post-prerequisite oracles.
A B2 refusal on the planning base returns exit 4 and the stable corrective
diagnostic instead of those gated outcomes.

| ID / command path | Invocation and semantic oracle | Attempts / retry | Artifacts and terminal oracle | Audit / output / exit oracle | B2/B3 disposition | Selector; criteria; tasks |
|---|---|---|---|---|---|---|
| C01 Success: setup -> run | DESCRIBE, VALIDATE and RUN EXITED with matching successful semantics | Attempt 1; no retry | F plus eligible E; COMPLETED / SUCCEEDED | Complete input/compatibility/queue/invocation/result/aggregate facts; separate refs; exit 0 | B2: blocked, including setup; B3 gates creation/queue replay and order | W::test_cli_success; 33.1/4-6, 33.4/1-9, 33.6/2-4; T3-T6 |
| C02 Warning: setup -> warning run | RUN EXITED 0 with valid warning semantics | Attempt 1; warning alone never retries | F retains warning; COMPLETED_WITH_WARNINGS / SUCCEEDED_WITH_WARNINGS | Warning and aggregate reasons visible; bounded warning; exit 0 | B2: blocked; inherits setup/B3 conditions | W::test_cli_warning; 33.3/5-6, 33.6/8,10-11; T4-T6 |
| C03 Partial success: two slots | One successful slot and one terminal failure/unavailable slot | Independent histories; resolve retries before aggregation | F only for successful slot; N for non-success; COMPLETED_WITH_WARNINGS | Every slot/reason visible; no averaging; exit 0 | B2: blocked; inherits setup/B3 conditions | W::test_cli_partial_success; 33.3/6, 33.5/1, 33.6/5; T4,T6 |
| C04 Preflight incompatibility: validate -> queue -> run | Frozen NOT_APPLICABLE slot launches no VALIDATE/RUN child | Zero attempts for excluded slot; no automatic retry | N; all excluded -> FAILED; no invented run row | Compatibility and NO_APPLICABLE_ENGINE facts; exit 5 | B2: blocked, including required compatibility/aggregate facts and setup | W::test_cli_all_not_applicable; 33.3/4-6, 33.6/5; T3-T6 |
| C05 Late incompatibility | VALIDATE or RUN EXITED 20 with matching NOT_APPLICABLE output | Attempt 1; hard non-retriable | N; eligible sanitized E only; sole slot -> FAILED / NOT_APPLICABLE | Exact captured category and late reason; exit 5 | B2: blocked; inherits setup | W::test_cli_late_not_applicable; 33.3/6, 33.4/5, 33.6/5; T4,T6 |
| C06 Preflight unavailability | Explicit missing runtime or frozen UNAVAILABLE observation; launch failure kept distinct | Zero attempts for frozen unavailable slot | N; only fact-supported DESCRIBE E; all unavailable -> FAILED | Observation/identity/aggregate reasons; missing-runtime correction; exit 6 | B2: blocked for complete mutation path; read-only catalog projection may proceed | W::test_cli_preflight_unavailable; 33.1/5, 33.3/6, 33.6/5; T3-T6 |
| C07 Attempt unavailability | FAILED_TO_START or EXITED 30 with matching output | Attempt 1; successor only through R6 and fresh same-adapter observation | N; eligible diagnostics/validation E; UNAVAILABLE after denial/exhaustion | Launch/availability/retry facts; history visible; exit 6 | B2: blocked; B3 gates ordered successor/restart facets | W::test_cli_attempt_unavailable; 33.3/6, 33.5/3-4, 33.6/5; T4,T6 |
| C08 Engine crash | Captured crash exit/category; no success inference | R6 only for a permitted retriable primary diagnostic | N; bounded eligible E; FAILED after denial/exhaustion | Captured outcome, primary diagnostic and aggregate; exit 7 | B2: blocked; inherits setup/retry gates | W::test_cli_crash; 33.4/5,8,10, 33.6/5,10; T4,T6 |
| C09 Protocol/security fault | Untrusted stdout -> PROTOCOL_FAILED; semantic defects preserve captured invocation facts | Hard block; no successor for protocol/security violation | N; independently sanitized E; unsafe candidates quarantined | Protocol rejection, identity/token/sequence facts; sanitized diagnostic; exit 8 | B2: blocked for complete supervised workflow; prelaunch grammar refusals remain executable | X::test_cli_protocol_refusals; 33.4/2-5,10-11, 33.7/1; T4,T6 |
| C10 Core timeout | Original DESCRIBE/VALIDATE/RUN deadline wins, including pre-handoff and VALIDATING | No reset; R6 only after terminal attempt and required cleanup | N; eligible E; no fabricated exit; linked run TIMED_OUT | Deadline selection/scope and cleanup/enrichment; exit 9 | B2: blocked; B3 gates ordered restart/retry facets | W::test_cli_deadlines; 33.4/6-8,10, 33.5/4; T4,T6-T7 |
| C11 Finalization timeout | RUN invocation stays EXITED; RESULT deadline wins independently | Run TIMED_OUT; only existing retry rules apply | N; journal timed out/abandoned; failed RESULT bytes quarantined; E separate | FINALIZATION_TIMED_OUT plus required terminal/aggregate facts; exit 9 | B2: blocked for full setup/aggregate path; supported artifact-only timeout facet may proceed independently | W::test_cli_finalization_timeout; 33.4/7-9, 33.6/5; T4,T6-T7 |
| C12 Owner cancellation | Durable cancellation wins; graceful interrupt then bounded forced cleanup if required | No successor after winning cancellation | N for cancelled work; earlier committed success immutable; active runs CANCELLED | Cancellation CAS, cleanup and terminal facts; request exit 0, driver exit 130 | B2: blocked before unsupported cancellation mutation; refusal path executable | W::test_cli_cancel; 33.4/6,10, 33.5/1,4; T4-T7 |
| C13 Cancellation loses RESULT race | Existing lease/terminal CAS winner controls | No reopening terminal run | Registered F retained; exact existing winner | Winner and replay/conflict facts; Matrix A exit | B2: blocked for unsupported cancellation/lifecycle mutation; supported immutable query remains executable | R::test_cli_cancel_finalization_races; 33.5/1, 33.6/2; T4,T7 |
| C14 Stale predecessor after retry | Old identity/token/event/candidate cannot satisfy successor | Successor only through R6; predecessor immutable | N for stale output; reject/quarantine; F only for valid successor | Stale rejection and successor linkage; both attempts visible | B2: blocked; B3 gates durable ordered retry/restart | R::test_cli_stale_attempt; 33.4/2,4, 33.5/3-5; T4,T6-T7 |
| C15 Captured-result restart | Durable RUN EXITED with captured exit/category; no matching live child | Same attempt; no replacement token | Recover F only after all 29.3 gates; E independent | Existing recovery/result actions plus required application facts; recovered refs; exit 0 | B2: blocked for complete resume/aggregate path; supported artifact-only recovery may proceed without unsupported mutation | R::test_cli_recover_captured_result; 33.4/8-9, 33.5/8, 33.6/2; T2,T7 |
| C16 Lost-exit restart | Missing native exit never creates EXITED; stdout-trust loss considered separately | Original deadline retained; successor only after terminal outcome and R6 | N; pending original deadline, then justified failure/timeout | Lost-fact, deadline and cleanup facts; exit 4 while unresolved, then 9 or 8 as applicable | B2: blocked for unsupported recovery transitions; read-only pending-state projection may proceed | R::test_cli_lost_exit; 33.4/7-8,10, 33.5/8; T2,T7 |
| C17 Killed child/owner | Both handoff sides; all nonterminal states; terminal incomplete cleanup | Requeue only proven prelaunch work; no duplicate possibly launched command | N without eligible captured result; exact recovered winner | Creation-identity/handoff/cleanup/reconciliation facts; Matrix A exit | B2: blocked for full mutated recovery; B3 gates requeue; child/owner refusal controls remain required | RC::test_cli_killed_child; 33.4/6-8,12, 33.5/8; T2,T7 |
| C18 Finalization crash points | Invocation already terminal; every required durable finalization phase covered | Same identity; no duplicate attempt | PREPARED/MOVED recovery or abandonment; REGISTERED replay; E independent | Existing phase/replay/abandonment/summary actions; exact refs and winner | B2: blocked for full setup/resume path; supported artifact-only cells proceed independently and prove only that facet | RF::test_cli_finalization_crash_points; 33.5/8,10, 33.6/2-6; T2,T7 |
| C19 Input/startup refusal | Failed gate produces no supervised invocation | No attempt/retry | No new candidate/ref/manifest; existing states unchanged | Bounded refusal; no fabricated unsupported rejection audit; exit 2/3/4 | B2: refusal proceeds; unsupported mutation remains blocked; no deferred audit assertion | X::test_cli_prelaunch_refusals; 33.2/2,9, 33.7/1-3; T1-T3,T5-T6 |
| C20 Candidate/hash/move refusal | Captured invocation preserved; artifact failure never implies success | Hard integrity block | N; quarantine/corrupt/abandon as applicable; E cannot alter prior terminal | Supported artifact facts plus required lifecycle facts; separated evidence; exit 1 | B2: blocked for full run/setup path; isolated supported artifact refusal facets may proceed | X::test_cli_artifact_refusals; 33.6/2-6,10; T4,T6-T7 |

C01-C18 and C20 therefore do not claim complete execution on this base.
C19, read-only projections and independently supported refusal/artifact facets
form the current bounded dispatch evidence.

Inherited B3 conditions concern creation replay and ordered scheduling.
They do not convert every artifact-only replay into a B3 obligation.

### 5.3 State, producer and projection clarifications

All-NOT_APPLICABLE aggregates to FAILED with
`EXPERIMENT.NO_APPLICABLE_ENGINE`.
It introduces no new experiment state.

The classifier returns COMPLETED_WITH_WARNINGS for the applicable partial-success
and warning cases. It never emits CANCELLED.

Source: `src/crypto_lab/domain/aggregation.py:401`.

Application cancellation owns its durable winner.
A cancelled slot without that experiment winner may aggregate to FAILED.

The aggregate service requires RUNNING for a new aggregation and separately
supports terminal replay.

Source: `src/crypto_lab/experiments/aggregation.py:385`.

Preserve the adapter's eight process-exit categories independently of CLI exits.
An adapter self-reporting cancellation/timeout without a core winner is an engine
runtime failure. DESCRIBE exit 20 is not strategy incompatibility.

Source: `src/crypto_lab/adapters/exit_codes.py:34`.

T6's post-prerequisite matrix covers 0, 10, 20, 30, 40, 50, 60 and 70.

Both conclusion routes require EXITED:

- `conclude_command` for VALIDATE/RUN.
- `conclude_describe` for DESCRIBE.

Sources:
`src/crypto_lab/experiments/finalization.py:3721`,
`src/crypto_lab/experiments/finalization.py:3999`.

The execution bridge never passes PROTOCOL_FAILED, TIMED_OUT, CANCELLED
or FAILED_TO_START through an EXITED-only conclusion route.
It preserves the actual winner and invokes independently eligible evidence
operations explicitly.

DESCRIBE receives no fabricated run or attempt token.

| Producer responsibility | Permitted output / authority | Tasks |
|---|---|---|
| Strategy canonical source snapshot | STRATEGY E qualified against registered owner/version/hash | T3 coordinates; T5 reads physical input |
| Dataset descriptor/partition snapshot | DATASET E with fixture provenance and registered identity | T3 coordinates; T5 confines and reads files |
| Frozen configuration/spec snapshot | EXPERIMENT E qualified against immutable durable facts | T3,T5 |
| DESCRIBE descriptor/stderr projection | ADAPTER E tied to the exact invocation | T4,T5 |
| VALIDATE/RUN protocol, stderr, diagnostic and sanitized-output projections | RUN E with exact invocation/source-candidate lineage | T4,T6 |
| Core system diagnostic/audit projection | SYSTEM E from an existing authoritative typed source | T3-T5; missing audit-derived facts B2-gated |
| Successful native/fixture-normalized candidates | RUN RESULT through production registrar/core manifest only | T4,T6; B1 remains |
| Failed native/normalized candidates and original raw control bytes | No conversion to EVIDENCE; no finalized reference | T4,T6-T7 |

T3 supplies the reader contract and tests its typed refusal seam with in-memory
doubles. It creates no concrete physical CLI reader.

T5's `cli/composition.py` owns physical strategy/dataset input confinement,
bounded reads and identity/swap checks before application registration.

D02 construction remains in T3's application module.
T5 passes copied by-value configuration fields and projects
`CONFIG.CATALOG_ENTRY_INVALID`; it does not duplicate that validation.

The existing engine identity has exactly `engine_name` and `engine_version`.

Source: `src/crypto_lab/domain/experiment.py:122`.

The selector aliases are fixed in section 7.3.
R is in-process recovery only.
RC and RF identify the two admitted real-child test modules.

Every row asserts database state, lifecycle history, audits, diagnostics,
temporary/final artifacts and child cleanup when its prerequisite permits it.

Source:
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2096`.

Successful status/evidence queries return exit 0 independently of the execution
state they describe.

---

## 6. Matrix D: exact file, guard, census, launcher and documentation reconciliation

### 6.1 Ownership rules and running counts

Matrix D records implementation ownership and coordinated reconciliation.
It creates no worker bounds.

The sole worker bounds remain each section 8 task's **Files created.**
and **Files modified.** paragraphs.

No directory, wildcard, implicit package marker or unnamed support file is
authorized by an ownership description here.
Create no `__init__.py` in the proposed CLI unit/integration test locations.

Any additional file requires a recorded D10 file-map correction before dispatch.
No floor file enters a worker manifest.

| Boundary | Source/package census | Import roots | Infrastructure pairs | Product launcher operations |
|---|---|---|---|---|
| Observed base | 135 | 30 | 17 | 21 |
| T1 | 137 | 33 | 19 | 21 |
| T2 | 138 | 33 | 19 | 21 |
| T3 | 139 | 33 | 19 | 21 |
| T4 | 141 | 33 | 19 | 21 |
| T5 | 144 | 34 | 19 | 21 |
| P1 | 144 | 34 | 19 | 22 |
| T6-T8 | 144 | 34 | 19 | 22 |

These are nominal counts against the identified base.
They include nine new source modules and no release of deferred canonical names.

D14 reinspects every count, membership set, source-text mirror and dependent
selector after a separately integrated correction.
Never preserve a nominal count against changed authoritative bytes.

The base complete-census assertions are at
`tests/safety/test_stage8_boundaries.py:1054`.

### 6.2 T1 ownership: runtime services, ports and guard foundation

T1 owns the proposed runtime module, inward application ports,
their units and the Stage 10 guard foundation.

Its produced interfaces are:

```text
cli/runtime.py::create_runtime_services
cli/runtime.py::probe_storage
cli/runtime.py::acquire_dispatch_owner
cli/runtime.py::release_dispatch_owner
experiments/application_ports.py structural query/execution/transaction ports
```

The ports contain immutable internal values and no concrete persistence,
configuration, process-supervision or CLI types.
They reach neither artifacts nor audit.

T1 advances all nine census owners to 137.
It adds only time/secrets/signal to the root set and the two reviewed
runtime/time and runtime/secrets infrastructure pairs.

It adds the exact ambient-clock exemption and controls from section 2.6:

```text
_AMBIENT_CLOCK_EXEMPTIONS ==
frozenset({("cli/runtime.py", "datetime.datetime.now")})
```

The exact proposed guard selector is:

`tests/safety/test_stage5_boundaries.py::test_each_ambient_clock_exemption_licenses_exactly_its_pair`

T1 adds only runtime to the ctypes importer set.
Runtime binds the required kernel32 functions itself at call time.
It does not expand the existing Windows API module or borrow an unreviewed
mutex/volume interface from it.

Preserve `types` confinement and every cwd/home/expanduser denial.

### 6.3 T2 ownership: startup, typed queries and phased artifact recovery

T2 owns the proposed startup coordinator, its units, detached startup-query
tests and the bounded extensions to existing database/reconciliation modules.

Its produced interfaces are:

```text
cli/startup.py::open_current_database
cli/startup.py::check_database
cli/startup.py::check_schema_distribution
cli/startup.py::check_storage
cli/startup.py::begin_reconciliation
cli/startup.py::inventory_work
cli/startup.py::reconcile_startup
cli/startup.py::reconcile_runs
cli/startup.py::permit_scheduling
reconcile_finalization(..., phase="inventory"|"recover"|"sweep")
```

The recovery extension and artifact-recovery tests belong to T2.
They add no source module and preserve the omitted-selector complete pass.

Advance source/package mirrors to 138.
Roots/pairs remain 33/19.

Admit exactly `experiments.application_ports` alongside `experiments.ports`
in the two extended persistence query modules' exact import sets,
family set and denial exception.

Preserve twelve SQLAlchemy and four Alembic importers.

Source: `tests/safety/test_stage8_boundaries.py:881`.

**Persistence direction is a separate T2 obligation.**

Carve out exactly the CLI package's named concrete persistence importers from
the Stage 8 outward-import loop:

- T2 introduces `cli/startup.py`.
- T5 adds `cli/composition.py`.
- T4/T5 adds `cli/execution.py` only if its actual reviewed implementation
  imports persistence.

Unused names are not pre-authorized.
The set must equal actual importer membership.

Application services, scheduler, application ports and every other non-CLI
package remain denied.

Add a planted `experiments/probe.py` persistence import that still fails.
Exercise the same direction-checking logic used by the real-tree guard.

The existing loop is at
`tests/safety/test_stage8_boundaries.py:940`.

This is the specification's CLI -> Persistence composition direction.

Source:
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:215`.

T2's broader regression targets include unchanged Stage 5, Stage 6 and Stage 7
guards in addition to its modified guards.

### 6.4 T3 ownership: explicit application inputs, compatibility and freeze

T3 owns `experiments/application.py`, application units and the input-boundary
unit module.

The latter's subject is the reader-contract and typed-input refusal seam of
`experiments/application.py`, exercised with in-memory doubles.
It does not claim physical-reader implementation.

T3 produces the by-value catalog-entry construction, explicit-input orchestration,
compatibility coordination, transaction joining and queue-freeze application seam.

D02 receives adapter name/version, executable path/hash and a copied metadata
mapping. It validates the reserved `engine_identity` as `EngineIdentity`,
removes that key from the copied catalog metadata and preserves the complete
configuration snapshot.

No configuration-model import enters application code.

Advance source/package mirrors to 139.
Roots/pairs remain 33/19.

Release only strategy/datasets application edges.
Keep concrete persistence, configuration, CLI and process-supervision denied.

Re-point the existing planted architecture strategy control to
`crypto_lab.process_supervision`.

Source:
`tests/architecture/test_package_import_boundaries.py:698`.

Re-point both released strategy/datasets parameter rows in the Stage 5
out-of-scope control to process-supervision shapes.
Preserve absolute/relative import-shape coverage.

Source: `tests/safety/test_stage5_boundaries.py:703`.

Add application to both Stage 9 importer sets.
Pin its reached package set to artifacts/audit.

Sources:
`tests/safety/test_stage9_boundaries.py:153`,
`tests/safety/test_stage9_boundaries.py:549`.

Required successful application-audit paths remain B2-gated.
Creation/queue replay and durable queue-order facts retain B3.

T3's broader regression targets include unchanged Stage 6/7 guards.

### 6.5 T4 ownership: scheduler and concrete execution bridge

T4 owns the scheduler, CLI execution bridge and their units.

Its produced interfaces include:

```text
experiments/scheduler.py::recover_queue
experiments/scheduler.py::drive
cli/execution.py structural execution-port implementation
```

The scheduler consumes structural ports.
The CLI bridge alone invokes/destructures concrete supervision outcomes.

Advance source/package mirrors to 141.
Roots/pairs remain 33/19.

Add only `cli/execution.py` to the additional asyncio importer allowance.
Add scheduler to both Stage 9 importer sets and pin its reached set to audit.

Retain application -> artifacts/audit.
Application ports reach neither package.

D06 releases no experiments -> process-supervision edge.
The Stage 5 and architecture denials remain.

The sole production Popen call stays in its existing owner.

Source: `tests/safety/test_stage7_boundaries.py:624`.

If execution actually imports persistence, reconcile the exact CLI importer set
and preserve T2's planted experiments control in this introducing task.
Otherwise add no such allowance.

T4 proves controlled concurrency overlap, not merely coroutine construction
or a capacity counter.

### 6.6 T5 ownership: grammar, concrete composition and projections

T5 owns the three proposed CLI composition/command/reporting modules,
the existing main entry point and their command/composition/reporting units.

Its produced interfaces are:

```text
cli/main.py::build_parser
cli/main.py::main
cli/composition.py::load_inputs
cli/composition.py::open_resources
cli/composition.py::close
cli/commands.py::parse_command
cli/commands.py typed operational command set
cli/reporting.py text/JSON projection functions
```

T5 passes D02's by-value inputs to T3 and projects its stable refusal.
It implements the concrete physically confined input readers.

Advance source/package mirrors to 144.
Add sys only to `cli/main.py` for argv/stdout/stderr wiring.
Roots become 34; infrastructure pairs remain 19.

Extend T2's exact CLI persistence-importer set with `cli/composition.py`.
Include execution only if it actually imports persistence.
Every other package stays denied.
The planted `experiments/probe.py` control still fails.

Preserve both unknown-argument controls:

- Existing harmless `--unknown` echo.
- T5's proposed nonmatching-token refusal without raw-value echo.

Source: `tests/unit/test_cli.py:68`.

P1 alone changes launcher bytes and operation pins.
T5 supplies its reviewed grammar and changes no launcher/floor file.

### 6.7 P1 operator ownership and launcher reconciliation

P1 follows T5's reviewed grammar and closes before T6 dispatch.
Its four-path operator change record and hook re-pin remain those in section 1.4.

This subsection creates no worker bound.

P1:

- Adds `cli-local` to the targeted-operation partition.
- Advances operations 21 -> 22.
- Preserves five bootstrap profiles and both closed switches.
- Enforces the absolute drive-letter path-token admission rule.
- Preserves each admitted path as one argument.
- Checks token shapes only; CLI owns filesystem/product semantics.
- Preserves offline/pinned execution, environment-removal names,
  fixed Pydantic hardening and native exit propagation.
- Advances the normalized launcher SHA pin.
- Changes `_ALLOWED_COMMANDS` only if the validator introduces a command AST entry.
- Adds targeted membership at the migration cross-pin without changing
  `_PYTHON_BEARING_OPERATIONS`.
- Preserves verifier bytes, neighbors and eleven-step order.

Pin owners:

`tests/safety/test_uv_launcher.py:15`,
`tests/safety/test_uv_launcher.py:18`,
`tests/safety/test_stage8_boundaries.py:1075`,
`tests/unit/persistence/test_sqlite_migrations.py:1072`.

Independent review, complete operator verification, the human commit and
committed-byte hook re-pin precede dependent dispatch.

Prove old-byte refusal and new-byte acceptance.
The worker hook still admits exactly its six profiles.
`cli-local` remains operator-run.

T8 owns README/guide profile documentation.
The protected AGENTS documentation companion remains separately operator-owned,
reviewed, verified and human-committed before T8's worker base.

Until those documentation changes land, identify inherited 21-profile prose
as stale.

### 6.8 T6 ownership and execution route

T6 owns the launch-free CLI support module, W/X/token acceptance modules,
extensions to the existing CLI test module and the Stage 10 guard.

Counts remain 144/34/19/22.

Normal W/X/TOK commands call production `main(argv)` in-process.
No helper imports `tests/unit/test_cli.py` as a library.

Any T6 selector requiring a real CLI child lives in `tests/unit/test_cli.py`.
That importer calls launch-free support helpers.

The new support and integration modules import no subprocess module.
Tests never invoke `cli-local`.

Required workflow selectors/facets are partitioned by Matrix C's B2/B3 markers.
T6's acceptance subject contains exactly the untagged selectors and refusal paths.
Gated facets are authored at D14 reinspection.

The T6 unsafe-argument integration control is separately named:

`tests/integration/cli/test_cli_boundaries.py::test_cli_unknown_argument_nonmatching_control`

It complements T5's unit control rather than replacing it.

Preserve contract/fake inventories, diagnostic readers and raw-token carriers.
The new CLI case inventory remains separate from earlier closed inventories.

### 6.9 T7 ownership and real-child placement

T7 owns the in-process recovery module and extensions to CLI support,
the two existing subprocess-importer modules and the Stage 10 guard.

Counts remain 144/34/19/22.
The subprocess-importer census remains thirteen.

| Proposed selector | Hosting module / route |
|---|---|
| `test_cli_cancel_finalization_races` | R; in-process |
| `test_cli_stale_attempt` | R; in-process unless a distinct real-child facet is placed in RC/RF |
| `test_cli_recover_captured_result` | R; in-process over explicitly established durable prestate |
| `test_cli_lost_exit` | R; in-process |
| `test_cli_killed_child` | RC; real CLI child |
| `test_cli_finalization_crash_points` | RF; existing crash discipline and real CLI recovery |
| `test_cli_survivor_observation_precedes_cleanup` | RC; real child and non-killing observation |
| `test_cli_wal_first_opener_waits_for_real_holder_exit` | RF; retained actual-interpreter/descendant handles |
| `test_cli_live_running_pid_reuse_is_not_adopted` | RC; actual identity-safe process control |
| `test_cli_startup_barrier` | R; deterministic in-process barrier cases |
| `test_cli_deadline_survives_restart` | R; reopened durable state |
| `test_cli_retry_delay_survives_restart` | R; reopened durable state; B2/B3-gated mutation facet |
| `test_cli_retry_after_restart` | R; B2/B3-gated |
| `test_cli_recovery_second_pass_is_idempotent` | R; supported artifact facet distinguished from gated full resume |

A selector needing a new real CLI child moves to RC/RF before dispatch.
Record the exact file-map/selector correction; do not add a fourteenth importer
or reverse the support dependency.

Observe matching survivors before cleanup.
Retain creation-identity handles for subsequent bounded cleanup.

Do not reopen SQLite until the actual interpreter and verified descendants
have terminated and been awaited.
Launcher exit alone is insufficient.

The existing retained-holder discipline is documented in
`tests/integration/artifacts/test_finalization_crash_child.py:13`.

### 6.10 T8 ownership: documentation and acceptance evidence

T8 owns the local CLI runbook, the Project 1 acceptance ledger,
README/guide/roadmap status reconciliation and their named guards.

This adds no source/package module, schema, hash profile, action or migration.

The separate protected AGENTS companion is operator-owned.
It documents the profile and changes no execution or safety authority.

Plan approval itself remains plan-only.
T8 later changes the roadmap's Planned -> Approved wording and the GitNexus
approved-plan sentence after actual plan acceptance.

Historical Stage 9 completion and evidence limits remain history.
They do not become Project 1 acceptance.

The proposed T7 implementation checkpoint and later T8 documentation commit
remain distinct. Record only an observed checkpoint hash.
No documentation commit self-references its future hash.

### 6.11 Guard-by-guard reconciliation ledger

All source citations below refer to the planning base.
Introducing tasks advance pins with their implementation.
T8 owns documentation-only reconciliation.

| Guard / source | Owner and exact treatment |
|---|---|
| Stage 3 source closure; `tests/safety/test_stage3_boundaries.py:432` | T1-T5 add exactly the nine proposed modules in sequence; 135 -> 137 -> 138 -> 139 -> 141 -> 144 |
| Dotted inventory; `tests/unit/test_package_layout.py:12` | T1-T5 append exact dotted names, including application_ports; retain fresh-import coverage and every historical positional slice |
| Database census; `tests/unit/persistence/test_sqlite_database.py:1806` | T1-T5 advance source/module/root literals and the quoted mirrors at :1860, :1861 and :1864; retain negative `== 95` and `== 27` pins |
| Migration census/mirrors; `tests/unit/persistence/test_sqlite_migrations.py:1039` | T1-T5 advance source/module/root literals and quoted preflight/reconciliation strings at :1059-1062 in lockstep |
| Preflight census; `tests/unit/process_supervision/test_supervisor_preflight.py:1242` | T1-T5 advance source/module/root totals; preserve supervisor placement and existing exports |
| Restart census; `tests/unit/process_supervision/test_restart_reconciliation.py:1754` | T1-T5 advance source/module totals; preserve reconciliation positional facts |
| Store census; `tests/unit/artifacts/test_artifact_store.py:2047` | T1-T5 advance source/module/root totals; preserve deferred-name count, store slice and os confinement |
| Stage 3 root equality; `tests/safety/test_stage3_boundaries.py:459` | T1 adds time/secrets/signal, 30 -> 33; T5 adds sys, 33 -> 34; update declaration and exact equality |
| `types`; `tests/safety/test_stage3_boundaries.py:197`, `tests/safety/test_stage3_boundaries.py:566` | All tasks preserve exactly strategy/models.py's MappingProxyType import; no new types importer |
| Forbidden path discovery; `tests/safety/test_stage3_boundaries.py:200` | Preserve cwd/home/expanduser denial in every new module |
| Infrastructure scanner; `tests/safety/test_stage5_boundaries.py:224` | T1 adds only runtime/time and runtime/secrets; 17 -> 19 |
| Whole-block exemption control; `tests/safety/test_stage5_boundaries.py:575` | T1 adds identical pairs to the exact equality; prove real import, denied sibling and planted-module cases |
| Migration exemption mirror; `tests/unit/persistence/test_sqlite_migrations.py:1065` | T1 advances exact literal/count to the identical nineteen pairs |
| Ambient clock scanner; `tests/safety/test_stage5_boundaries.py:233` | T1 adds only `_AMBIENT_CLOCK_EXEMPTIONS == frozenset({("cli/runtime.py", "datetime.datetime.now")})` |
| Tree-wide clock/environment test; `tests/safety/test_stage5_boundaries.py:425` | Consult the clock exemption only; preserve environment denial unchanged |
| Clock control shapes; `tests/safety/test_stage5_boundaries.py:654`, `tests/safety/test_stage5_boundaries.py:658` | Preserve both existing tests; add exact pair-by-pair exemption selector and reviewed near misses |
| Stage 7 root confinement; `tests/safety/test_stage7_boundaries.py:147` | T1 adds runtime to ctypes; T4 adds execution to asyncio; threading/queue/subprocess memberships unchanged |
| Sole production launch; `tests/safety/test_stage7_boundaries.py:624` | Preserve one Popen and its reviewed arguments/keywords; no additional launch implementation |
| Stage 5 application closure; `tests/safety/test_stage5_boundaries.py:148` | T3 releases strategy/datasets only; keeps process_supervision/persistence/cli denied; Stage 10 also denies configuration |
| Stage 5 planted shapes; `tests/safety/test_stage5_boundaries.py:703` | T3 re-points both released-edge examples to process_supervision and preserves shape coverage |
| Architecture planted edge; `tests/architecture/test_package_import_boundaries.py:698` | T3 plants process_supervision instead of newly permitted strategy |
| Stage 8 source arithmetic; `tests/safety/test_stage8_boundaries.py:850` | T1-T5 advance actual/allowed totals; preserve historical fifteen-file membership and disjointness |
| Stage 8 complete census; `tests/safety/test_stage8_boundaries.py:1054` | Advance only task-owned source/root/pair values and P1 operation value; preserve readers 5, subprocess 13, requirements 4, prohibited families 27 and verifier 10/11 |
| Stage 8 infrastructure arithmetic; `tests/safety/test_stage8_boundaries.py:881` | T1 changes persistence-pair `+ 1` to `+ 3`, naming both runtime additions; SQLAlchemy/Alembic stay 12/4 |
| Stage 8 persistence import sets; `tests/safety/test_stage8_boundaries.py:201`, `tests/safety/test_stage8_boundaries.py:417`, `tests/safety/test_stage8_boundaries.py:904` | T2 admits application_ports only in the two extended query modules and the closed family/exception sets |
| Stage 8 persistence direction; `tests/safety/test_stage8_boundaries.py:940` | T2 creates exact named CLI carve-out for startup; T5 extends with composition; execution only if actual; every other package denied; planted experiments/probe.py still fails |
| Stage 9 historical arithmetic; `tests/safety/test_stage9_boundaries.py:496` | T1-T5 subtract a separately named cumulative Stage 10 set; retain historical 25-file set, excluded branch and pre-Stage-5 remainder 51 |
| Stage 9 importer sets; `tests/safety/test_stage9_boundaries.py:153`, `tests/safety/test_stage9_boundaries.py:160` | T3/T4 add application/scheduler to permitted and actual sets; actual 2 -> 3 -> 4 |
| Stage 9 reached sets; `tests/safety/test_stage9_boundaries.py:549` | Pin application -> artifacts/audit and scheduler -> audit; retain original per-module facts and tree-wide experiments -> persistence denial |
| Stage 9 os confinement; `tests/safety/test_stage9_boundaries.py:581` | Advance root count only; artifacts/store.py remains sole importer with fstat/fsync only |
| Raw-token carriers; `tests/safety/test_stage6_boundaries.py:315` | Preserve exactly four reviewed carriers and wrapper near miss; no raw string token field on new records |
| Test/script subprocess closure; `tests/safety/test_stage6_boundaries.py:106`, `tests/safety/test_stage6_boundaries.py:372` | Preserve thirteen importers; RC/RF host real-child selectors; support stays launch-free |
| Fake roots; `tests/safety/test_stage6_boundaries.py:97` | Preserve seven roots and existing fake/contract inventories; add no new fake program |
| Diagnostic readers/traversal; `tests/safety/test_stage5_boundaries.py:474`, `tests/safety/test_stage5_boundaries.py:493` | Preserve five reader implementations and retry.py's sole causal traversal |
| Released/deferred names; `tests/safety/test_stage9_boundaries.py:634` | Preserve twenty released and thirteen deferred ownership facts; no Stage 10 release |
| Schema positions; `tests/safety/test_stage9_boundaries.py:662` | Preserve 48 entries, Stage 9 positions 35:48 and all digest blocks; D14 handles external corrections |
| Hash/action contracts; `tests/safety/test_stage9_boundaries.py:651`, `tests/safety/test_stage9_boundaries.py:704` | Preserve twenty hash profiles and twenty-five actions in Stage 10 changes |
| Migration chain; `tests/safety/test_stage9_boundaries.py:689` | Preserve r0001_stage8_baseline -> r0002_stage9_artifacts and one head |
| Existing contract inventory; `tests/integration/process_supervision/test_supervised_contract_matrix.py:214` | Preserve 52 numbered rows/58 entries and six supervision scenarios; CLI inventory remains separate |
| Launcher pin owners | P1 alone performs section 6.7's operation/hash/partition reconciliation |
| Verifier profile/digest pins; `tests/safety/test_stage3_boundaries.py:222`, `tests/safety/test_stage3_boundaries.py:234` | Preserve ten profiles, eleven steps and exact verifier bytes |

**Census mirrors advance; they are not preserved at old values.**

The database quoted source assertions inspect preflight/reconciliation literals.
Advance those strings with the inspected literals in every introducing task.

Sources:
`tests/unit/persistence/test_sqlite_database.py:1856`,
`tests/unit/persistence/test_sqlite_migrations.py:1056`.

Preserve the negative historical pins.
Append new dotted names outside all existing positional slices, including:

- Database adjacency:
  `tests/unit/persistence/test_sqlite_database.py:1849`.
- Migration adjacency:
  `tests/unit/persistence/test_sqlite_migrations.py:1048`.
- Supervisor adjacency:
  `tests/unit/process_supervision/test_supervisor_preflight.py:1253`.
- Restart membership/position facts:
  `tests/unit/process_supervision/test_restart_reconciliation.py:1763`.
- Artifact-store slice:
  `tests/unit/artifacts/test_artifact_store.py:2058`.

**New root permissions remain module-specific.**

Only runtime gains time/secrets/signal and the extra ctypes edge.
Only execution gains the extra asyncio edge.
Only main gains sys for argv and stream wiring.

No new io/random/msvcrt/logging/tempfile/shutil/subprocess/queue/threading
or types importer is admitted.

No new os importer or os attribute is admitted.

New CLI importlib use is limited to metadata/resources.
It authorizes neither arbitrary import nor discovery.

The runtime clock exemption:

- Requires the real licensed read.
- Rejects utcnow/date.today in runtime.
- Rejects now in main and planted cli/probe.py.
- Resolves aliases identically.
- Preserves fresh-import failure for eager draws.
- Grants no environment access.

### 6.12 T8 documentation assertions and dispositions

T8 reconciles exact assertions per file.
It does not remove broad guards to admit arbitrary later-stage claims.

| Guard / source | Required documentation treatment |
|---|---|
| Stage 3 setup; `tests/safety/test_stage3_boundaries.py:1132` | Preserve README Local setup heading, boundaries, preamble, five commands and following prose verbatim |
| Setup commands; `tests/safety/test_stage3_boundaries.py:1147` | Preserve uv version, managed discovery, sync, cli-version and cli-module-version lines |
| Setup prose; `tests/safety/test_stage3_boundaries.py:1157` | Preserve prerequisite/offline/acquisition-limit wording; operational examples belong outside this block |
| Stage 3 status owner; `tests/safety/test_stage3_boundaries.py:1865` | Move exact roadmap/README/guide status pins together; retain history and hash rules |
| Stage 3 positive status assertions; `tests/safety/test_stage3_boundaries.py:1934` | Reconcile current header/approved-plan/status constants truthfully; preserve earlier approved-plan and retired-status negatives |
| Shared historical obligations; `tests/safety/test_stage3_boundaries.py:1659` | Preserve `_VERIFICATION_STAGE9_OBLIGATIONS` byte-for-byte; new closure evidence sits outside the passage |
| Shared obligations assertions; `tests/safety/test_stage3_boundaries.py:1955`, `tests/safety/test_stage9_boundaries.py:788` | Keep the same imported constant; do not invent a second independently edited copy |
| Stage 3 subtraction; `tests/safety/test_stage3_boundaries.py:1999` | Add exact new approved status/closure blocks to subtraction operands before new Stage 10 prose; retain residual Stage 10 and `exhaustiv` restrictions |
| Stage 5 containment; `tests/safety/test_stage5_boundaries.py:536` | Reconcile exact approved README blocks; preserve denial of stray Stage 10 and every Stage 11 claim |
| Stage 7 history/status; `tests/safety/test_stage7_boundaries.py:770` | Preserve Stage 9 completion/history facts; replace start denial at :777 only with exact evidenced status |
| Stage 7 documentation limits; `tests/safety/test_stage7_boundaries.py:802` | Preserve whole-document README/guide prohibition on unsupported OS-isolation claims and the guarded term |
| Stage 7 subprocess prose; `tests/safety/test_stage7_boundaries.py:792` | Preserve the thirteen-importer guide sentence; selected test route adds no importer |
| Stage 8 later claims; `tests/safety/test_stage8_boundaries.py:637` | Replace only exact truthful status permissions; keep unproved completion/Stages 1-10 forms denied |
| Stage 8 historical rows; `tests/safety/test_stage8_boundaries.py:1088` | Preserve Stage 8 row ending Stage 9 complete, retired deferred-row denials and historical hashes |
| Stage 8 claim loop; `tests/safety/test_stage8_boundaries.py:1131` | Retain state-aware later-claim protection |
| Stage 8 not-started twins; `tests/safety/test_stage8_boundaries.py:1138`, `tests/safety/test_stage8_boundaries.py:1139` | Replace README "Stage 10 has not started." and guide "Stage 10 is not started." with Stage 9's twin reconciliation; retain Stage 9 not-started denials |
| Stage 9 deferred row; `tests/safety/test_stage9_boundaries.py:731` | Replace `_STAGE10_DEFERRED_ROW` membership with approved-plan/evidenced implementation state |
| Stage 9 active count; `tests/safety/test_stage9_boundaries.py:742` | Reconcile the one not-started count and forward clause only after implementation starts |
| Stage 9 header; `tests/safety/test_stage9_boundaries.py:746` | Replace active Stages 1-9 header truthfully while retaining historical Stages 1-9 facts |
| Stage 9 not-started twins; `tests/safety/test_stage9_boundaries.py:751` | Reconcile README/guide together with Stage 8's pins; keep acceptance blockers explicit |
| Stage 9 historical hashes; `tests/safety/test_stage9_boundaries.py:763` | Keep each earlier checkpoint once in roadmap and absent from README/guide; record only observed Stage 10 checkpoint |
| Stage 9 focused history; `tests/safety/test_stage9_boundaries.py:780` | Preserve six focused commands, pinned prose, shared historical obligations, runtime-rule register and revision names |
| Guide registry wording; `tests/safety/test_stage9_boundaries.py:790` | Preserve closed 48-file statement; deny retired closed 35-file wording |
| README registry list; `tests/safety/test_stage9_boundaries.py:797` | Preserve closed 48-schema sentence and thirteen Stage 9 schema paths unless D14 reinspects an integrated correction |
| GitNexus approval sentence; `tests/safety/test_gitnexus_development_tooling.py:371` | T8 advances approved detailed-plan count only after plan acceptance; preserve DISABLED_WITH_EVIDENCE |
| Launcher documentation; `AGENTS.md:17` | Operator companion updates protected AGENTS prose; T8 updates README outside Local setup and the guide |
| Acceptance ledger | Record all 62 cells, exact selectors, subjects, commands, results, prerequisites and NOT CLOSED dispositions |

The Stage 8 twin assertions are at :1138/:1139 in this checkout.
The review's :1139 reference identifies that same coordinated status obligation.

The shared historical obligations constant is defined once in Stage 3
and consumed by Stage 9.
Preserving that constant preserves both assertions.
New closure evidence receives its own exact guarded block.

The six historical focused target tails remain:

```text
tests\unit\artifacts tests\unit\audit -q
tests\unit\persistence tests\unit\domain -q
tests\integration\artifacts -q
tests\unit\experiments tests\property -q
tests\integration\persistence -q
tests\safety tests\architecture tests\unit\test_schema_registry.py -q
```

Preserve their existing complete launcher command lines.
Their generator remains at
`tests/safety/test_stage9_boundaries.py:780`.

The historical limitations passage includes the pending survivor-observation
and conformant VALIDATE byte-scan gaps.

Source: `docs/development/verification.md:1158`.

T8 appends subsequent evidence outside that passage.
It does not retrospectively improve Stage 9's recorded result.

No README/roadmap/guide claim states Stage 10 or Project 1 complete while
B1, B2 or a necessary B3 disposition remains open.

### 6.13 Verifier step preservation

The unchanged ordered steps remain:

1. `lock-check`.
2. `sync`.
3. `ruff-format-all`.
4. `ruff-check-all`.
5. `mypy-all`.
6. `schema-generate-check`.
7. `migration-check`.
8. `pytest-all`.
9. `build`.
10. `schema-distribution`.
11. Direct `git diff --check`.

Sources:
`scripts/verify.ps1:21`,
`scripts/verify.ps1:46`,
`scripts/verify.ps1:56`,
`scripts/verify.ps1:71`.

Preserve its pinned SHA-256:

```text
ec818bc7551984878f2f4e57845ec7417b68839d889496acb3e43cb5c895ea7d
```

Source: `tests/safety/test_stage3_boundaries.py:234`.

New tests enter existing discovery.
There is no twelfth step or alternate acceptance verifier.

Workers use only the six profiles in Global Constraints.
Complete verification, operational `cli-local`, synchronization and builds
remain operator-run.

No network access, acquisition, engine installation or Project 2 dependency
is introduced.

---

## 7. Test strategy, harness and the requirement map

### 7.1 Layers, support and execution discipline

| Layer | Required Stage 10 proof |
|---|---|
| Unit | Call-time runtime facilities; inward ports; startup gates/order; input validation; transaction joining; freeze; scheduler claims/retries; parser/projections |
| Contract | Fresh complete existing fake-adapter protocol and repository-port suites; unchanged inventories |
| Integration | Production CLI composition over explicit fixtures, SQLite, supervisor, finalizer, registrar and structured output |
| Windows/process | Real children where required; handoff/owner crashes; identity-safe cleanup; deadlines; actual concurrent overlap |
| Safety/architecture | Closed source/import sets; no ambient values; narrow runtime exceptions; inward application direction; preserved exclusions |
| Property | Existing bounded canonical/hash/state/path/token properties under unchanged settings |
| Migration/distribution | Existing migration chain/object, generated-byte, source, wheel and sdist checks |
| Documentation/evidence | Exact status/profile assertions, historical limits and the complete 62-cell ledger |

Specification section 28 remains mandatory.

Sources:
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:1960`,
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2096`,
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2098`,
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2120`.

| Support | Reuse / limit |
|---|---|
| FixedClock and SequentialIdentitySource | Deterministic unit time/identity; no wall-clock sleeping; `tests/doubles/experiments.py:596`, `tests/doubles/experiments.py:623` |
| InMemoryUnitOfWork | Transaction-isolated unit doubles; no new diagnostic-reader implementation; `tests/doubles/experiments.py:1387` |
| ScriptedProcessController | Exact lifecycle/interleaving controls; `tests/doubles/supervision.py:471` |
| SqliteHarness | Fresh-reader durable visibility; tracked transaction cleanup; `tests/persistence_support/harness.py:804` |
| SupervisedSqliteFlow | Existing separated database/supervision-root discipline; `tests/persistence_support/supervised.py:281` |
| FinalizingSupervisedFlow | Existing production finalization support; does not replace CLI composition; `tests/persistence_support/artifacts.py:2043` |
| Proposed CLI support | Launch-free fixture/argv/output/snapshot/byte-scan helpers; no subprocess import |
| Existing CLI importer | Hosts real CLI child selectors and calls support helpers; `tests/unit/test_cli.py:7` |
| Existing crash-child importer | Retains verified actual-holder/descendant handles; `tests/integration/artifacts/test_finalization_crash_child.py:13` |

New records use existing token wrappers.
They add no raw-token string field carrier.

Fresh-import coverage includes every new source module before construction.
Preserve the existing fresh-import selector.

Source: `tests/unit/test_package_layout.py:264`.

Add planted eager clock/entropy/Windows-binding/signal controls.
The existing planted import-time side-effect control supplies the pattern.

Source: `tests/unit/test_package_layout.py:376`.

No production module imports test support.
No test module becomes a support library.

Real CLI child launch code stays in RC/RF.
Use a closed argv, `shell=False`, bounded waits and a fresh literal child
environment containing the exact Pydantic disable-all control before startup.
Inspect no ambient value.

That explicit child-environment construction is new reviewed launcher behavior,
not an assertion about the inherited helpers.
The existing CLI helper currently supplies no `env=` argument.

Source: `tests/unit/test_cli.py:19`.

Existing fake-adapter process execution remains through the production supervisor.
The test route does not authorize a new production process launcher.

### 7.2 RED/GREEN evidence and dispatch partition

Every RED record identifies its intended failure.
An unrelated interpreter, package or host failure does not establish RED.

For a new module's negative property:

- Record missing-module collection failure as the initial RED.
- After GREEN, prove the assertion detects a planted violating implementation.
- Do not present ImportError alone as proof of laziness or side-effect rejection.

For the new W/X suite, record initial collection failure from the absent support
and acceptance modules. After GREEN, a planted wrong-outcome control, such as
changing the expected exit by one, must fail.

| Task | Module-qualified RED examples / subject | GREEN and broader proof |
|---|---|---|
| T1 | U1::test_runtime_clock_is_utc; U1::test_runtime_identities_validate; U1::test_runtime_construction_is_explicit; S10::test_runtime_roots_are_module_scoped | Runtime/port units; planted eager initialization fails; fresh imports; exact clock/import near misses |
| T2 | U2::test_startup_phases_precede_scheduling; U2::test_failed_phase_never_permits_scheduling; U2::test_database_gate; U2::test_schema_distribution_matches_registry | Ordered trace; detached/reopened queries; twelve-field classification; closed phase selector; unchanged default recovery/details |
| T3 | U3::test_input_hashes_are_recomputed; U3::test_catalog_requires_explicit_identity; IB::test_explicit_inputs_reject_unknown_fields; U3::test_required_application_audit_unavailable_refuses_mutation | Pure/reader-contract/refusal subjects; exact importer controls; gated successful audit/replay facets wait for D14 |
| T4 | U4::test_startup_permit_is_required; U4::test_concurrency_is_bounded_and_overlaps; U5::test_non_exited_outcome_bypasses_conclusion_helpers | Structural unit interleavings, actual controlled overlap and refusal paths; production audited dispatch remains gated |
| T5 | U6::test_operational_grammar_is_closed; UC::test_help_and_version_construct_no_runtime; UC::test_composition_is_explicit_and_lazy; U7::test_projection_never_dumps_untrusted_material | Planted eager clock/entropy/database-open controls fail; grammar/exits/projections; existing CLI regression; concrete physical readers |
| T6 | X::test_cli_prelaunch_refusals; X::test_cli_unknown_argument_nonmatching_control; TOK::test_cli_token_scan_positive_control | Production parser/refusal paths and independent scanner control; full workflow/token-bearing execution selectors retain gates |
| T7 | R::test_cli_startup_barrier; RC::test_cli_survivor_observation_precedes_cleanup; RF::test_cli_wal_first_opener_waits_for_real_holder_exit | Correct host modules, pre-cleanup observations, retained-holder ordering, supported recovery facets; full mutated resume remains gated |
| T8 | S10::test_stage10_documentation_status_is_exact; S10::test_stage10_acceptance_ledger_has_all_62_cells; S10::test_stage10_coverage_evidence_is_measured | Exact coordinated prose/ledger checks; fresh operator evidence; no guessed coverage or completion |

IB is T3's application reader-contract subject.
UC is T5's concrete composition subject.
They prove different boundaries.

The proposed ambient exemption selector keeps its full exact name:

`tests/safety/test_stage5_boundaries.py::test_each_ambient_clock_exemption_licenses_exactly_its_pair`

It proves:

- Exactly the declared pair.
- A real licensed read.
- Denied utcnow/date.today in runtime.
- Denied now in main and planted cli/probe.py.
- Equivalent alias handling.
- Unchanged environment denial.

**Gated selector/facet ownership.**

The following require explicit gate tags when section 8 lists them:

| Owner | Gated success selector/facet |
|---|---|
| T3 | U3::test_joined_service_commit_is_deferred: successful required-audit publication facet, B2 |
| T3 | U3::test_queue_freezes_complete_snapshot: commit-together audit/queue-fact facet, B2/B3 |
| T3 | U3::test_queue_replay_and_conflict, B2/B3 |
| T3 | U3::test_creation_replay_uses_stored_creation_instant, B2/B3 |
| T3 | U3::test_input_evidence_matches_owner_and_registry: audit-derived SYSTEM facet, B2 |
| T4 | U4::test_queue_order_uses_original_queue_fact, B2/B3 |
| T4 | U4::test_retry_delay_uses_durable_instant: full audited scheduler/restart facet, B2/B3 |
| T4 | U5::test_trace_audit_refusal_blocks_associated_transition: successful atomic application-audit facet, B2 |
| T5 | Successful concrete mutation branches and their audit projections, B2; correlated creation/queue replay also B3 |
| T6 | Matrix C full workflow selectors marked blocked; W::test_cli_approximation and W::test_cli_input_and_system_evidence successful application/audit facets, B2 |
| T6 | TOK::test_cli_run_and_validate_token_absence complete conformant production workflow, B2 and inherited setup/B3 conditions |
| T7 | Mutating full resume/requeue/cancellation/retry workflow facets, B2 and applicable B3 |

Each B2 entry carries:

`(B2-gated: authored at the D14 reinspection after integration; not part of this dispatch)`

Each B3 entry additionally carries:

`(B3-gated: authored at the D14 reinspection after integration; not part of this dispatch)`

B2 refusal/rollback controls remain untagged.
Do not gate away the test that proves unavailable required audit capability
prevents mutation.

Current T3-T7 bounded acceptance contains the explicitly untagged selectors
and refusal paths.
No skip, xfail, marker or ignored failure substitutes for absent prerequisites.

After focused GREEN, run applicable guard/regression sets and the five
worker-callable quality profiles, serially.
Every accepted task still requires independent APPROVE and the operator's
complete PASSED verifier on the same subject.

### 7.3 Evidence keys, exact selectors and notation

`33.x/n` means the nth specification bullet in subsection 33.x.

The map has exactly 62 rows:

```text
6 + 9 + 8 + 13 + 10 + 11 + 5 = 62
```

Authorities:

`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2309`,
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2318`,
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2330`,
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2341`,
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2357`,
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2370`,
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2384`.

E01-E32 below identify existing source/assertion evidence read in this checkout.
They do not report fresh execution.
Their current runtime results are UNVERIFIED.

A listed selector is a required evidence target, not a closed criterion.
T8 records the exact subject, command, result, transcript/artifact reference,
prerequisites and limitations.

| Key | Existing module::test selectors and source citations |
|---|---|
| E01 | `tests/safety/test_project_dependencies.py::test_project_runtime_dependencies_are_exact` - `tests/safety/test_project_dependencies.py:150`; launcher/type gates remain required |
| E02 | `tests/safety/test_project_dependencies.py::test_project_has_no_prohibited_runtime_dependency` - `tests/safety/test_project_dependencies.py:159`; `tests/architecture/test_domain_import_boundary.py::test_repository_domain_package_has_no_prohibited_imports` - `tests/architecture/test_domain_import_boundary.py:193` |
| E03 | `tests/integration/process_supervision/test_supervised_contract_matrix.py::test_every_stage_six_row_passes_through_the_production_supervisor` - `tests/integration/process_supervision/test_supervised_contract_matrix.py:128` |
| E04 | `tests/unit/adapters/test_adapter_catalog.py::test_a_registered_identity_is_returned_without_reading_the_clock` - `tests/unit/adapters/test_adapter_catalog.py:250`; `tests/unit/adapters/test_adapter_catalog.py::test_a_missing_identity_is_an_unavailable_failure_stamped_by_the_clock` - `tests/unit/adapters/test_adapter_catalog.py:263` |
| E05 | `tests/unit/persistence/test_sqlite_constraints.py::test_every_trigger_and_state_check_fires` - `tests/unit/persistence/test_sqlite_constraints.py:2128`; `tests/unit/persistence/test_sqlite_constraints.py::test_the_permitted_writes_pass` - `tests/unit/persistence/test_sqlite_constraints.py:2148` |
| E06 | `tests/unit/test_schema_registry.py::test_stage_nine_entries_rendered_and_registered` - `tests/unit/test_schema_registry.py:1270`; `tests/unit/test_schema_registry.py::test_every_rendered_schema_equals_its_committed_generated_file` - `tests/unit/test_schema_registry.py:1405` |
| E07 | `tests/unit/artifacts/test_artifact_models.py::test_unknown_fields_and_implicit_none_rejected` - `tests/unit/artifacts/test_artifact_models.py:757`; `tests/unit/domain/test_experiment_records.py::test_every_task_two_model_rejects_an_unknown_field` - `tests/unit/domain/test_experiment_records.py:362` |
| E08 | `tests/unit/domain/test_financial.py::test_typed_decimal_serializes_as_canonical_fixed_point` - `tests/unit/domain/test_financial.py:48`; `tests/unit/domain/test_financial.py::test_python_mode_rejects_every_non_decimal` - `tests/unit/domain/test_financial.py:58` |
| E09 | `tests/unit/domain/test_time.py::test_utc_python_and_json_round_trip_are_canonical` - `tests/unit/domain/test_time.py:30`; `tests/unit/domain/test_time.py::test_python_validation_rejects_non_typed_or_non_utc_values` - `tests/unit/domain/test_time.py:55` |
| E10 | `tests/unit/domain/test_identifiers.py::test_prefixed_uuid4_alias_accepts_only_its_canonical_family` - `tests/unit/domain/test_identifiers.py:54` |
| E11 | `tests/unit/domain/test_hashing.py::test_sha256_and_attempt_token_goldens` - `tests/unit/domain/test_hashing.py:28`; `tests/property/test_dataset_hashing.py::test_hash_is_deterministic_and_material_field_sensitive` - `tests/property/test_dataset_hashing.py:109`; `tests/property/test_experiment_spec_hash.py::test_two_specs_differing_in_one_field_have_different_spec_hashes` - `tests/property/test_experiment_spec_hash.py:367` |
| E12 | `tests/unit/domain/test_experiment_records.py::test_the_freeze_predicate_refuses_a_retry_policy_byte_mismatch` - `tests/unit/domain/test_experiment_records.py:1118`; `tests/unit/persistence/test_sqlite_repositories.py::test_a_frozen_spec_cannot_change_after_queued` - `tests/unit/persistence/test_sqlite_repositories.py:289` |
| E13 | `tests/unit/persistence/test_sqlite_stage9_migration.py::test_upgrade_from_r0001_equals_fresh_r0002` - `tests/unit/persistence/test_sqlite_stage9_migration.py:120` |
| E14 | `tests/unit/strategy/test_strategy_loader.py::test_a_complete_valid_strategy_loads_into_a_strategy_version` - `tests/unit/strategy/test_strategy_loader.py:101`; `tests/unit/strategy/test_strategy_loader.py::test_an_adversarial_document_fails_at_the_yaml_boundary` - `tests/unit/strategy/test_strategy_loader.py:259` |
| E15 | `tests/unit/capabilities/test_capability_vocabulary.py::test_the_vocabulary_is_exactly_the_twenty_six_specification_names` - `tests/unit/capabilities/test_capability_vocabulary.py:59` |
| E16 | `tests/unit/capabilities/test_capability_resolver.py::test_identical_inputs_produce_byte_identical_results` - `tests/unit/capabilities/test_capability_resolver.py:221`; `tests/unit/capabilities/test_capability_resolver.py::test_an_allowed_declared_approximation_is_supported_with_approximation` - `tests/unit/capabilities/test_capability_resolver.py:567`; `tests/unit/capabilities/test_capability_resolver.py::test_a_compatible_but_unavailable_runtime_is_unavailable` - `tests/unit/capabilities/test_capability_resolver.py:879`; `tests/unit/capabilities/test_capability_resolver.py::test_a_live_runtime_request_never_reaches_an_outcome` - `tests/unit/capabilities/test_capability_resolver.py:270` |
| E17 | `tests/unit/experiments/test_comparison_eligibility_service.py::test_two_manifests_adapt_to_comparison_inputs` - `tests/unit/experiments/test_comparison_eligibility_service.py:88`; `tests/unit/experiments/test_comparison_eligibility_service.py::test_requested_level_above_provenance_refused` - `tests/unit/experiments/test_comparison_eligibility_service.py:133`; `tests/unit/capabilities/test_capability_comparison.py::test_no_public_symbol_averages_votes_combines_or_promotes` - `tests/unit/capabilities/test_capability_comparison.py:1346` |
| E18 | `tests/unit/domain/test_lifecycle_tables.py::test_the_command_invocation_machine_is_eight_states_64_pairs_ten_edges` - `tests/unit/domain/test_lifecycle_tables.py:328`; `tests/unit/domain/test_lifecycle_tables.py::test_the_frozen_native_exit_mapping_is_exactly_the_eight_specified_values` - `tests/unit/domain/test_lifecycle_tables.py:413` |
| E19 | `tests/unit/persistence/test_sqlite_run_events.py::test_append_event_replays_identical_and_refuses_conflicting_content` - `tests/unit/persistence/test_sqlite_run_events.py:28`; `tests/contract/test_validate_contract.py::test_a_stale_attempt_result_fails_every_identity_field` - `tests/contract/test_validate_contract.py:194` |
| E20 | `tests/unit/process_supervision/test_restart_reconciliation.py::test_an_absent_process_waits_for_its_deadline_and_never_becomes_exited` - `tests/unit/process_supervision/test_restart_reconciliation.py:822`; `tests/unit/process_supervision/test_restart_reconciliation.py::test_a_terminal_with_incomplete_cleanup_is_cleaned_and_enriched_once` - `tests/unit/process_supervision/test_restart_reconciliation.py:855` |
| E21 | `tests/unit/experiments/test_retry_decision.py::test_all_six_gates_passing_allows_reserves_and_bumps_the_experiment` - `tests/unit/experiments/test_retry_decision.py:976`; `tests/unit/experiments/test_retry_decision.py::test_every_hard_blocking_category_denies_a_listed_retriable_predecessor` - `tests/unit/experiments/test_retry_decision.py:1195`; `tests/unit/experiments/test_retry_decision.py::test_a_fresh_observation_of_the_same_adapter_identity_allows_the_retry` - `tests/unit/experiments/test_retry_decision.py:1281` |
| E22 | `tests/unit/experiments/test_successor_creation.py::test_the_successor_is_attempt_two_linked_to_the_predecessor_at_revision_zero` - `tests/unit/experiments/test_successor_creation.py:408`; `tests/unit/experiments/test_successor_creation.py::test_a_cancellation_winner_leaves_no_successor_durable` - `tests/unit/experiments/test_successor_creation.py:679`; `tests/unit/experiments/test_successor_creation.py::test_the_durable_delay_survives_a_rebuilt_service_over_the_same_store` - `tests/unit/experiments/test_successor_creation.py:974` |
| E23 | `tests/unit/persistence/test_sqlite_database.py::test_open_applies_and_reads_back_every_pragma` - `tests/unit/persistence/test_sqlite_database.py:247`; `tests/unit/persistence/test_sqlite_unit_of_work.py::test_a_commit_publishes_and_a_rollback_discards_for_a_fresh_reader` - `tests/unit/persistence/test_sqlite_unit_of_work.py:212` |
| E24 | `tests/integration/persistence/test_sqlite_restart_reconciliation.py::test_every_reconciliation_row_over_a_reopened_database` - `tests/integration/persistence/test_sqlite_restart_reconciliation.py:751`; `tests/integration/persistence/test_stage9_supervised_finalization.py::test_every_crash_point_through_production_registrar` - `tests/integration/persistence/test_stage9_supervised_finalization.py:932` |
| E25 | `tests/unit/datasets/test_dataset_models.py::test_dataset_models_round_trip_with_explicit_arrays` - `tests/unit/datasets/test_dataset_models.py:98`; `tests/unit/datasets/test_dataset_metadata_hashing.py::test_hash_is_deterministic_and_identity_validation_is_explicit` - `tests/unit/datasets/test_dataset_metadata_hashing.py:179` |
| E26 | `tests/integration/persistence/test_stage9_supervised_finalization.py::test_both_purposes_share_the_pipeline_only_result_succeeds` - `tests/integration/persistence/test_stage9_supervised_finalization.py:1292`; `tests/integration/persistence/test_stage9_supervised_finalization.py::test_owner_variants_end_to_end` - `tests/integration/persistence/test_stage9_supervised_finalization.py:1064` |
| E27 | `tests/unit/experiments/test_run_manifest.py::test_only_matching_run_result_refs` - `tests/unit/experiments/test_run_manifest.py:101`; `tests/unit/experiments/test_run_manifest.py::test_exit_category_from_exited_invocation` - `tests/unit/experiments/test_run_manifest.py:163`; `tests/unit/experiments/test_run_manifest.py::test_provenance_fields_retained` - `tests/unit/experiments/test_run_manifest.py:217` |
| E28 | `tests/integration/persistence/test_stage9_supervised_finalization.py::test_failure_row_keeps_only_evidence` - `tests/integration/persistence/test_stage9_supervised_finalization.py:538`; `tests/integration/persistence/test_stage9_supervised_finalization.py::test_native_output_preserved_as_result_only_on_success` - `tests/integration/persistence/test_stage9_supervised_finalization.py:1238`; `tests/integration/persistence/test_stage9_supervised_finalization.py::test_failure_exposes_code_category_retriable_evidence` - `tests/integration/persistence/test_stage9_supervised_finalization.py:1349` |
| E29 | `tests/integration/persistence/test_stage9_token_absence.py::test_token_absent_from_every_surface` - `tests/integration/persistence/test_stage9_token_absence.py:168`; `tests/integration/persistence/test_stage9_token_absence.py::test_positive_control_scan_is_exact_bytes` - `tests/integration/persistence/test_stage9_token_absence.py:197` |
| E30 | `tests/unit/audit/test_jsonl_log.py::test_record_schema_rotation_and_retention` - `tests/unit/audit/test_jsonl_log.py:83`; `tests/unit/audit/test_jsonl_log.py::test_redaction_before_serialization` - `tests/unit/audit/test_jsonl_log.py:144`; `tests/unit/persistence/test_sqlite_audit_sink.py::test_append_only_and_sequence_ordered` - `tests/unit/persistence/test_sqlite_audit_sink.py:114` |
| E31 | `tests/integration/process_supervision/test_windows_paths.py::test_long_paths_succeed_when_supported_and_are_rejected_deterministically_otherwise` - `tests/integration/process_supervision/test_windows_paths.py:262`; `tests/integration/process_supervision/test_windows_process_identity.py::test_a_live_process_with_a_different_creation_time_is_not_ours` - `tests/integration/process_supervision/test_windows_process_identity.py:86` |
| E32 | `tests/safety/test_uv_launcher.py::test_launcher_disables_real_pydantic_plugin_discovery_and_leaves_parent_unchanged` - `tests/safety/test_uv_launcher.py:1308`; `tests/unit/test_package_layout.py::test_all_planned_modules_import_fresh_without_observable_side_effects` - `tests/unit/test_package_layout.py:264` |

Proposed selector aliases expand to these exact modules:

| Alias | Module |
|---|---|
| U1 | `tests/unit/cli/test_runtime.py` |
| U2 | `tests/unit/cli/test_startup.py` |
| U3 | `tests/unit/experiments/test_application_service.py` |
| U4 | `tests/unit/experiments/test_scheduler.py` |
| U5 | `tests/unit/cli/test_execution.py` |
| U6 | `tests/unit/cli/test_commands.py` |
| U7 | `tests/unit/cli/test_reporting.py` |
| UC | `tests/unit/cli/test_composition.py` |
| IB | `tests/unit/cli/test_input_boundaries.py` |
| S10 | `tests/safety/test_stage10_boundaries.py` |
| W | `tests/integration/cli/test_cli_workflows.py` |
| X | `tests/integration/cli/test_cli_boundaries.py` |
| TOK | `tests/integration/cli/test_cli_token_absence.py` |
| R | `tests/integration/cli/test_cli_recovery.py` |
| RC | `tests/unit/test_cli.py` |
| RF | `tests/integration/artifacts/test_finalization_crash_child.py` |
| LEDGER | `docs/development/project-1-acceptance.md` |

`G2` and `G3` below are references to the exact B2/B3 tags in section 7.2.
They identify future successful selectors/facets absent from the current dispatch.
They are not pytest markers or skip mechanisms.

### 7.4 Complete section 33 requirement map

The task column records scoped implementation, preservation and evidence
contributions from Matrices A-C.

T8 owns final evidence reconciliation for all 62 rows.
A task contribution does not mean that task independently closes the criterion.

All rows remain execution-UNVERIFIED in this planning turn.
A blocked row retains its NOT CLOSED disposition even when partial existing
evidence passes.

| Criterion | Existing evidence and required Stage 10 closing evidence | Tasks / disposition |
|---|---|---|
| 33.1/1 Managed Python 3.12, strict typing and uv | E01,E32; managed discovery; launcher confinement; mypy-all; existing CLI version tests; LEDGER | T1,T5,T8 |
| 33.1/2 No real engine installed/imported/required | E02; S10::test_stage10_installed_distributions_exclude_real_engines; bounded metadata review without engine import or ambient inspection | T8; installed state UNVERIFIED |
| 33.1/3 Pure domain dependency direction | E02; existing package-boundary suites; S10::test_application_ports_are_inward_only; exact concrete-import carve-outs | T1-T5,T8 |
| 33.1/4 Isolated argv-only adapter operations | E03; U5::test_only_supervisor_executes_commands; startup permit; C01/C09; no alternate launcher | T2-T8; complete workflows G2 |
| 33.1/5 Explicit catalog only | E04; U3::test_catalog_requires_explicit_identity; descriptor/slot agreement; C06/X refusals | T3-T6,T8; successful descriptor/application facts G2 |
| 33.1/6 Core sole writer/system of record | E05,E23,E26; transactional registration; U5::test_launch_has_no_database_access; durable workflow snapshots | T2-T8; application facts G2; creation replay G3 |
| 33.2/1 Required section 11 records/schemas | E06 and B08 provide partial closed-registry evidence only; required normalized family remains absent | T2,T8; B1 NOT CLOSED BY STAGE 10 |
| 33.2/2 Unknown fields rejected | E07,E03; X::test_cli_unknown_fields; U3/IB strict inputs; C19; safe parser refusals | T1-T3,T5-T6,T8; successful downstream workflow facets G2 |
| 33.2/3 Decimal and canonical financial strings | E08; X::test_cli_decimal_inputs; strict application boundaries; no float coercion in reporting | T3,T5-T6,T8 |
| 33.2/4 UTC/Z timestamps; naive values fail | E09; U1::test_runtime_clock_is_utc; C01 timestamp assertions G2 | T1,T6,T8 |
| 33.2/5 Validated prefixed UUID4 IDs | E10; U1::test_runtime_identities_validate; C01 and successor identity assertions | T1,T3-T8; actual creation/retry workflow facets G2/G3 |
| 33.2/6 Deterministic SHA-256 identities | E11; B08 byte checks; U3::test_input_hashes_are_recomputed; C01/replay material equality | T2-T3,T5-T6,T8; successful replay G2/G3 |
| 33.2/7 Strict retry/state/purpose/owner schemas | E06,E18; owner branches at `tests/unit/test_schema_registry.py:799`; B08 and unchanged distribution bytes | T2-T3,T5-T6,T8; preserve contracts, no schema addition |
| 33.2/8 Retry policy embedded, hashed and frozen | E11,E12; U3::test_queue_freezes_complete_snapshot; X::test_cli_material_override_conflict | T3,T5-T6,T8; complete atomic queue/replay G2/G3, NOT CLOSED |
| 33.2/9 Explicit migrations preserve history | E13; U2::test_normal_startup_never_migrates; maintenance command tests; C19; killed-holder/reopen evidence | T1-T3,T5-T8; required migration audit G2 |
| 33.3/1 Safe declarative YAML | E14; X::test_cli_strategy_input_boundary; T5 bounded physical reader | T3,T5-T6,T8; registration success G2 |
| 33.3/2 Complete deterministic strategy v1 | E14; existing strategy/feature/expression suites; canonical source/hash composition | T3,T5-T6,T8; complete registration/workflow G2 |
| 33.3/3 Complete capability vocabulary | E15; fresh vocabulary/resolver suites; S10 preservation checks | T8 |
| 33.3/4 Four deterministic compatibility outcomes | E16; U3::test_all_compatibility_outcomes; C01/C04/C06 | T3-T6,T8; durable decision/workflow facts G2 |
| 33.3/5 Approximation impacts/exclusions | E16,E17; W::test_cli_approximation; U7::test_approximation_reasons_survive_projection | T3-T6,T8; successful application/audit facet G2 |
| 33.3/6 Incompatibility/unavailability remain distinct | E16; C03-C07; exact per-slot and aggregate reasons | T3-T6,T8; complete mutation paths G2 |
| 33.3/7 Three comparison levels; no voting/averaging | E17; U6::test_comparison_command; X::test_cli_comparison_exclusions; immutable registered-manifest queries | T5-T6,T8 |
| 33.3/8 Reject runtime.live | E16; X::test_cli_runtime_live_rejected_before_launch; zero invocation/attempt assertions | T3,T5-T6,T8; refusal executable |
| 33.4/1 DESCRIBE/VALIDATE/RUN contracts | E03; full unchanged contract suite; C01/C05/C07 through production bridge | T3-T6,T8; complete CLI workflows G2 |
| 33.4/2 Exact invocation identity throughout | E03,E19; X::test_cli_protocol_refusals; C14; request/event/output and stale-attempt checks | T3-T8; complete mutation paths G2 |
| 33.4/3 Negotiated versioned schemas | E03,E06; U3::test_descriptor_negotiation_agreement; core support test at `tests/unit/adapters/test_protocol_negotiation.py:456` | T3-T6,T8; durable negotiation facts G2 |
| 33.4/4 Invocation/sequence uniqueness and replay | E19; X::test_cli_event_replay_conflict; C09/C14; durable constraints | T3-T8; successful event/application path G2 |
| 33.4/5 Exact eight process-exit categories | E18; E03; U5::test_process_exit_category_preserved; distinct CLI exit projections | T3-T6,T8; full CLI process rows G2 |
| 33.4/6 Lifecycle/CAS/identity/cleanup/enrichment | E05,E18,E20; B09/B13/B19; C10/C12/C17; all-pairs/coupling suites | T1-T8; unsupported lifecycle/cancellation facts G2 |
| 33.4/7 Snapshotted paired deadlines; no reset | E03,E20; W::test_cli_deadlines; C11; R::test_cli_deadline_survives_restart | T2-T8; complete CLI mutation paths G2 |
| 33.4/8 Captured exits; no inferred recovery success | E20,E27; C15/C16; R::test_cli_lost_exit; absent manifest on lost facts | T2-T8; supported artifact facet separate; full resume G2 |
| 33.4/9 Zero exit needs matching manifest; core owns RunManifest | E03,E26-E28; X::test_cli_zero_exit_without_manifest; C01/C15; registrar atomicity | T2-T8; full workflow G2 |
| 33.4/10 Exact protocol/crash/heartbeat/cancel/termination mappings | E03; C08-C12/C16-C17; exact primary diagnostics and original terminal winners | T2-T8; full mutation paths G2 |
| 33.4/11 Hash-only authoritative/finalized token representation | E29; TOK::test_cli_run_and_validate_token_absence; C14-C18; positive exact-byte scanner control | T2-T8; conformant full workflow G2; gap remains until executed |
| 33.4/12 Windows paths, cleanup, PID reuse and restart | E20,E24,E31; U1 ownership tests; RC::test_cli_killed_child; RC::test_cli_live_running_pid_reuse_is_not_adopted | T1-T2,T5,T7-T8; defect returns to Stage 7 correction |
| 33.4/13 No OS-level isolation claim | Existing guard at `tests/safety/test_stage7_boundaries.py:802`; S10 help/documentation scan | T8 |
| 33.5/1 Allowed/forbidden transitions atomic | E05,E18; U3 audit rollback/refusal; U4 races; C12/C13; fresh-reader visibility | T2-T8; complete audit-coupled closure G2 |
| 33.5/2 Immutability from QUEUED | E12; U3::test_queue_replay_and_conflict; X::test_cli_material_override_conflict; persisted hashes after reopen | T3-T6,T8; correlated creation/queue replay G2/G3, NOT CLOSED |
| 33.5/3 Fresh successors and bounded attempt count | E21,E22; U4::test_successor_has_fresh_material; R::test_cli_retry_after_restart; immutable predecessors | T1-T8; complete audited ordered retry G2/G3 |
| 33.5/4 Six retry gates, hard blocks, durable delay and races | E21,E22; U4::test_retry_gates; R::test_cli_retry_delay_survives_restart; C07/C10/C12 | T2-T8; complete ordered scheduling/requeue G2/G3 |
| 33.5/5 Stale events/children cannot finalize successor | E19; C14; R::test_cli_stale_attempt; stale writer at `tests/integration/process_supervision/test_windows_open_handles.py:238` | T2-T8; full successor workflow G2/G3 |
| 33.5/6 WAL/FKs/migrations/UoW/CAS | E05,E13,E23; U2::test_database_gate; RF::test_cli_wal_first_opener_waits_for_real_holder_exit | T2,T5,T7-T8 |
| 33.5/7 Adapter cannot write core database | U5::test_launch_has_no_database_access; X::test_cli_adapter_write_boundary; existing path separation at `tests/persistence_support/supervised.py:281` | T4,T6,T8; full launch facet G2 |
| 33.5/8 Complete startup/handoff/cleanup/finalization recovery | E20,E24; Matrix B; C15-C18; R::test_cli_startup_barrier; second-pass replay | T1-T2,T4-T8; full mutation path G2; ordered requeue G3 |
| 33.5/9 Invocation/run agreement and event indexes | E05,E19; detached-query checks; X::test_cli_event_replay_conflict; per-row consistency | T2,T4,T6-T8; full workflow facts G2 |
| 33.5/10 State/deadline/retry/owner/purpose/journal constraints | E05; journal identity test at `tests/unit/persistence/test_sqlite_finalization_journal.py:125`; C11/C18/C20 | T2,T5-T8; no schema weakening |
| 33.6/1 Dataset provenance/quality/checksums, fixtures only | E25; T3 reader contract; T5 physical confinement; X::test_cli_dataset_confinement; C19 | T1-T3,T5-T6,T8; registration success G2 |
| 33.6/2 Both purpose pipelines; only RESULT succeeds | E26; C01/C11/C18/C20; production registrar and independent RESULT/EVIDENCE identities | T2-T8; full setup/aggregate G2 |
| 33.6/3 Candidate/ref separation and mandatory lineage | E07,E26; C01/C18/C20; independent source-candidate/owner/purpose assertions | T2-T8; full workflow G2 |
| 33.6/4 RunManifest accepts matching RUN RESULT only | E27; X::test_cli_manifest_membership; C01/C03/C18; registrar queries | T2-T8; full workflow G2 |
| 33.6/5 Non-success has no RESULT/RunManifest | E28; C04-C12/C14/C16-C20; W::test_cli_non_success_has_no_result; zero-registration queries | T2-T8; complete CLI matrix G2 |
| 33.6/6 Only permitted sanitized EVIDENCE finalizes | E26,E28,E29; X::test_cli_evidence_roles; C09/C18/C20; failed-result/raw-control negatives | T2,T4-T8; full workflow G2 |
| 33.6/7 Exact owner variants and RUN-only run links | E26; producer table; W::test_cli_input_and_system_evidence; no invented owner/run | T2-T8; input/application and audit-derived SYSTEM facets G2 |
| 33.6/8 Native/normalized RESULT only on success/warning | E28; C01/C02/C20; fixture-normalized role proof explicitly partial | T2,T4-T8; B1 normalized-family scope NOT CLOSED; full workflow G2 |
| 33.6/9 Complete normalized-record provenance | E27 is provenance-contract evidence only; recovery/distribution checks cannot supply missing record execution | T2,T7-T8; B1 NOT CLOSED BY STAGE 10 |
| 33.6/10 Stable actionable machine-readable diagnostics | E28; U7::test_diagnostic_projection; C04-C12/C20; JSON/text equivalence and query semantics | T4-T8; full outcome matrix G2 |
| 33.6/11 Bounded local correlated token-free logs/audits | E29,E30; retention snapshot, trace projection, transaction-refusal and exact-byte scans | T2-T8; B2 NOT CLOSED; artifact-only audit/log evidence is partial |
| 33.7/1 No forbidden API/network/shell/pickle/plugin surface | E01-E03,E32; S10 closed grammar/runtime/import scans; C19 | T1-T8 |
| 33.7/2 Fixed Pydantic control before relevant children | E32; P1 argv/environment/path admission; admitted RC/RF child launchers; no control in product data | P1,T1-T3,T5-T6,T8; operator and child-route evidence required |
| 33.7/3 All Project 1 exclusions | E01,E02; fixture-only workflows; forbidden-path test at `tests/safety/test_forbidden_runtime_paths.py:138`; docs/diff review | T1-T8 |
| 33.7/4 Seven engines remain future intents | E02; explicit catalog/future-intent projection; README list at `README.md:9`; bounded installed metadata | T3,T5,T8; installed state UNVERIFIED |
| 33.7/5 Complete offline fake-only suite passes | Exact candidate and merged-main complete verifier; independent review/security/diff evidence; all required cells closed | T8; no closure while B1/B2/necessary B3 remains |

**Exact inverse for section 8 criteria paragraphs.**

These sets include scoped preservation contributions.
They do not authorize additional implementation files or close gated facets.

Each task's criteria paragraph must equal exactly the rows naming that task above:

| Task | Exact criteria set |
|---|---|
| T1 | 33.1/1,3; 33.2/2,4-5,9; 33.4/6,12; 33.5/3,8; 33.6/1; 33.7/1-3 |
| T2 | 33.1/3-4,6; 33.2/1-2,6-7,9; 33.4/6-12; 33.5/1,3-6,8-10; 33.6/1-9,11; 33.7/1-3 |
| T3 | 33.1/3-6; 33.2/2-3,5-9; 33.3/1-2,4-6,8; 33.4/1-11; 33.5/1-5; 33.6/1-5,7,11; 33.7/1-4 |
| T4 | 33.1/3-6; 33.2/5; 33.3/4-6; 33.4/1-11; 33.5/1-5,7-9; 33.6/2-8,10-11; 33.7/1,3 |
| T5 | 33.1/1,3-6; 33.2/2-3,5-9; 33.3/1-2,4-8; 33.4/1-12; 33.5/1-6,8,10; 33.6/1-8,10-11; 33.7/1-4 |
| T6 | 33.1/4-6; 33.2/2-9; 33.3/1-2,4-8; 33.4/1-11; 33.5/1-5,7-10; 33.6/1-8,10-11; 33.7/1-3 |
| T7 | 33.1/4,6; 33.2/5,9; 33.4/2,4,6-12; 33.5/1,3-6,8-10; 33.6/2-11; 33.7/1,3 |
| T8 | 33.1/1-6; 33.2/1-9; 33.3/1-8; 33.4/1-13; 33.5/1-10; 33.6/1-11; 33.7/1-5 |

P1 contributes to 33.7/2 outside worker dispatch.
T8's all-cell responsibility is final evidence reconciliation, not a claim
that documentation closes runtime criteria.

D14 refreshes the map, its inverse, affected selectors and dispatch subjects
together after any corrective integration.

### 7.5 Blocked-cell ownership and evidence limits

**B1 - BLOCKED: required normalized canonical records.**

The existing normalized-provenance model/schema and JSON role fixtures are
partial evidence. They cannot supply the absent normalized record family.

The guide records the deferred family and absent normalized producer.

Source: `docs/development/verification.md:1122`.

Retain NOT CLOSED for:

- 33.2/1.
- Normalized-family portions of 33.6/8.
- 33.6/9.

Resolution requires the owner-approved owning-stage canonical/schema route
and D14 reinspection.
Stage 10 adds no normalized converter, Parquet implementation or canonical family.

**B2 - BLOCKED: application audit vocabulary.**

The current twenty-five actions cannot be repurposed as the missing application
facts.

Source: `src/crypto_lab/audit/models.py:61`.

Unsupported audit-dependent mutations refuse before mutation and launch.
Logging, a refusal projection or a passing artifact-audit test does not close B2.

The NOT CLOSED set includes:

- 33.6/11.
- Required audit facets of 33.5/1, 33.2/8 and 33.6/7.
- Every full Matrix C row marked B2: blocked, including C01, C04 and C07.
- The corresponding G2 startup, maintenance, invocation, retry, cancellation
  and application-mutation facets explicitly identified in section 7.4.

Resolution requires the owner-approved owning-stage audit/persistence correction,
compatibility/migration evidence and D14 reinspection.

Current refusal tests prove the boundary.
They do not prove successful audited dispatch.

**B3 - CONDITIONAL BLOCKER: durable scheduling and creation idempotency.**

Retain the original QUEUED-CAS instant with the immutable queued spec.
A later mutable update timestamp, creation timestamp or in-memory cache
cannot substitute for that fact.

The queue operation stamps its replacement at the observed CAS construction.

Source: `src/crypto_lab/experiments/experiment_service.py:483`.

The current experiment row has created/updated timestamps without a dedicated
queue field, and the creation request has no correlation field.

Sources:
`src/crypto_lab/persistence/schema.py:514`,
`src/crypto_lab/experiments/requests.py:123`.

The existing-durable-fact branch remains proposed and UNVERIFIED.
It depends on B2 and independent atomicity, restart, ordering and replay proof.

Retain conditional NOT CLOSED for:

- Correlated creation replay in 33.1/6.
- Complete queue/freeze replay in 33.2/8 and 33.5/2.
- Ordered retry/requeue portions of 33.5/4 and 33.5/8.

If existing facts cannot prove the guarantees, use the owner-held correction
for a column, request field, schema/migration or specification amendment.
Stage 10 adds none silently.

**Platform obligation.**

The live RUNNING PID-reuse finding remains a required cell.

Source: `docs/development/verification.md:1133`.

A failing cell returns to its Stage 7 corrective owner.
T7 does not expand into unreviewed supervisor implementation work.

### 7.6 Token, survivor and restart harness requirements

E29 supplies the existing exact-byte scanner positive-control pattern.

Source: `tests/integration/persistence/test_stage9_token_absence.py:197`.

The proposed independent scanner must visit:

- Database bytes.
- Present live WAL/SHM sidecars.
- Queried serialized columns.
- Logs, diagnostics and audits.
- CLI projections.
- Finalized objects and artifacts.
- Staging and quarantine.
- Every command root of the attempt, including conformant token-bearing VALIDATE
  request/output roots and RUN roots.

Record absent optional sidecars explicitly.
Unreadable required surfaces fail; they do not count as empty.

Scan after the relevant terminal cleanup/recovery point and before teardown.
Keep fixture roots available through the scan.
Do not establish absence by deleting the fixture first.

Prove exact raw-token bytes were the needle.
Distinguish a hash, altered needle and split/noncontiguous bytes.
Production redaction/scanning cannot be its own independent oracle.

The conformant VALIDATE execution row retains its B2/setup gates.
The independent planted scanner control remains executable without that workflow.
Neither replaces the other.

The historical VALIDATE and survivor-observation limits remain recorded.

Source: `docs/development/verification.md:1158`.

For survivor proof:

1. Observe matching live children without killing them.
2. Record the set and durable creation identities.
3. Freeze that observation for the leak assertion.
4. Perform bounded, identity-verified cleanup in `finally`.

A detected survivor fails leak detection even when cleanup later succeeds.
Do not use a terminating sweep as the observation oracle.

For killed writers:

1. Retain handles while the actual interpreter and verified descendants are alive.
2. Verify creation/executable identity.
3. Terminate and await through those handles within bounds.
4. Inspect actual exit facts.
5. Reap any launcher separately.
6. Prove verified descendants exited.
7. Reopen SQLite only then.

The inherited crash-child fixture explains why launcher exit alone is insufficient.

Source: `tests/integration/artifacts/test_finalization_crash_child.py:13`.

A second recovery pass must create no duplicate attempt, ref, manifest
or terminal transition.
Expected summary audit rows are distinguished from substantive changes.

No restart reconstructs a missing raw token.
Surviving temporary material is usable only through the existing purpose,
identity, named-hash and lease checks.

### 7.7 Skip inventory and positional attribution

Preserve these three skip-capable source sites:

| Site | Treatment |
|---|---|
| `tests/safety/test_uv_launcher.py:928` | Conditional symbolic-link privilege skip; preserve its platform limitation |
| `tests/unit/experiments/test_experiment_service.py:811` | Same-state transition cases are covered by separate replay cases; preserve parametrization |
| `tests/safety/test_uv_launcher.py:1312` | Pydantic importorskip exists but must not actually skip in the managed environment |

These are source sites, not today's measured skipped-instance count.

The carried record documents positional skip attribution and its limitation.

Source:
`docs/superpowers/plans/2026-08-10-project-1-artifact-finalization-recovery-provenance-audit-implementation-plan.md:2908`.

Retain complete-verifier progress positions.
Where reasons are absent, correlate collected parametrized ordering and the
inventory where possible.
Label the attribution positional.

Do not invent reason-level certainty or promote historical counts into a
current measurement.

Add no skip, xfail, marker, ignored failure or timeout relaxation.
A Pydantic skip is a failed prerequisite.

### 7.8 Measured coverage, reruns and fresh evidence

P0 measures the complete-verifier branch-coverage baseline on unchanged
product code at:

```text
874fb51b4959ca6c3b8e5a2bc640b9af99b176f1
```

The actual coverage, test/skip counts, warnings and elapsed time remain UNVERIFIED.

T8 records baseline, candidate and merged-main evidence under unchanged
measurement settings.

Final coverage must meet both:

- The measured unchanged-base baseline.
- The configured 90 percent floor.

Sources: `pyproject.toml:96`, `pyproject.toml:105`.

Do not round the baseline down, exclude new modules or change configuration.
Focused `-o addopts=` runs prove focused behavior only.
They do not supply acceptance coverage.

For the carried open-handle-count intermittent, allow one isolated rerun
of the failing command, alone on the host.

Retain both outcomes and every earlier failure.
A passing rerun does not establish a fix.
A second failure stops acceptance for diagnosis.
The exact final subject still requires a PASSED complete verifier.

Source:
`docs/superpowers/plans/2026-08-10-project-1-artifact-finalization-recovery-provenance-audit-implementation-plan.md:2906`.

Fresh evidence identifies:

- Exact commit or frozen precommit subject digest.
- Parent and accepted manifest.
- Corrective/prerequisite state.
- Exact admitted command.
- Native result and complete transcript.
- Scope, warnings, skips and unrun later steps.
- Review/verifier identities and limitations.

Older stage passes, plan review, focused GREEN, a build or one fake success
do not establish Stage 10 acceptance.

Full verification remains the operator-run command:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

Preserve serial host-lock execution and exact subject matching.
Report every failure and every NOT RUN later step.

This continuation performed read-only source/record inspection.
It changed no repository file and ran no project Python, managed-interpreter
discovery, test, schema generator, build or verifier.

All proposed execution remains UNVERIFIED.
No acceptance or completion token follows from this plan text.

Every roadmap exclusion remains binding.

Source:
`docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md:276`.

## 8. Task decomposition

Execute serially:

```text
P0 -> T1 -> T2 -> T3 -> T4 -> T5 -> P1 -> T6 -> T7
-> operator AGENTS documentation companion -> T8
-> authorized integration and merged-main acceptance
```

P2 corrective integrations enter only through D14 reinspection.
A dependent dispatch must reflect the integrated interfaces, guards and criteria.
Do not assume a future correction's signatures or published fields.

Dispatch one worker per task.
Its exact bounds are the paths in that task's **Files created.** and
**Files modified.** paragraphs, and nowhere else.
Repeated guard paths authorize only the introducing task's required reconciliation.
Create no `__init__.py` in the proposed CLI unit or integration test locations.
Additional files require a recorded D10 correction before dispatch.

No worker bound includes a policy-floor file.
P1 and the protected AGENTS documentation companion remain operator-owned.

Each task consumes accepted predecessors.
Use an injected structural port when a later implementation is needed.
A missing required implementation refuses its operation.

Follow focused RED -> minimum GREEN -> focused GREEN -> broader checks ->
independent review -> complete operator verification on the same subject.
Record the intended RED failure.
An unrelated interpreter, dependency or host failure does not establish RED.

For a new module's negative property, record missing-module collection failure
as the initial RED.
After GREEN, prove that a planted violating implementation fails the assertion.
ImportError alone does not prove laziness, confinement or side-effect rejection.

Run checks serially under the shared host verifier lock.
Do not overlap tests, review, edits or complete verification.
Focused `-o addopts=` runs supply no acceptance coverage measurement.
Every accepted task requires independent APPROVE and complete PASSED verification
covering the same parent, manifest and subject bytes.

All selectors and interfaces introduced below are proposed and execution-UNVERIFIED.
Aliases have exactly the module expansions in section 7.3.
Gated selectors/facets are absent from the current dispatch, not skipped or xfailed.

Use these tags literally where applicable:

```text
(B2-gated: authored at the D14 reinspection after integration; not part of this dispatch)
(B3-gated: authored at the D14 reinspection after integration; not part of this dispatch)
(B2-gated | B3-gated: authored at the D14 reinspection after integration; not part of this dispatch)
```

A task's acceptance subject is exactly its untagged selectors plus the refusal paths.
Tagged successful facets cannot be counted as passing or closed.
Structural unit doubles may prove orchestration without authorizing an unsupported
production mutation or fabricating an `AuditAction`.

The **Section 33 criteria closed** paragraphs reproduce section 7.4's exact inverse.
They identify scoped implementation, preservation and evidence contributions.
They do not claim execution, whole-criterion closure or closure of blocked facets.

Before execution, confirm:

```text
uv python find --managed-python --system --no-python-downloads 3.12
```

Stop if the managed interpreter or required offline packages are unavailable.
No acquisition is authorized.
Source: `AGENTS.md:12`.

Preserve every exclusion: new architecture; unplanned canonical or relational
schema changes; real market data; real engines/backtests; Binance integration;
live or paper trading; wallet, risk, tax, UI, LLM, Docker, cloud, server,
optimization and promotion features.
Also exclude credentials, API keys, withdrawals, leverage, futures, margin,
shorting, implicit network access, dependency acquisition and Project 2
dependencies in the core environment.

Sources:
`docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md:276`,
`AGENTS.md:33`,
`AGENTS.md:40`.

### Task 1 - Runtime services, application ports and Stage 10 guard foundation

**Objective.** Supply explicitly constructed clocks, identities, cancellation,
Windows storage probes and process-released dispatch ownership.
Define inward application query, execution and transaction contracts.

**Prerequisites.** Accepted plan, P0, sufficient authorized controller capacity
and the reviewed Stage 10 implementation binding.
Managed Python and offline prerequisites must be established before execution.

**Interfaces produced.**
`cli/runtime.py::create_runtime_services`,
`cli/runtime.py::probe_storage`,
`cli/runtime.py::acquire_dispatch_owner`,
`cli/runtime.py::release_dispatch_owner`;
`experiments/application_ports.py` structural query/execution/transaction ports
and immutable internal values.

**Files created.**
`src/crypto_lab/cli/runtime.py`
`src/crypto_lab/experiments/application_ports.py`
`tests/unit/cli/test_runtime.py`
`tests/unit/experiments/test_application_ports.py`
`tests/safety/test_stage10_boundaries.py`

**Files modified.**
`tests/safety/test_stage3_boundaries.py`
`tests/safety/test_stage8_boundaries.py`
`tests/safety/test_stage9_boundaries.py`
`tests/unit/test_package_layout.py`
`tests/unit/persistence/test_sqlite_database.py`
`tests/unit/persistence/test_sqlite_migrations.py`
`tests/unit/process_supervision/test_supervisor_preflight.py`
`tests/unit/process_supervision/test_restart_reconciliation.py`
`tests/unit/artifacts/test_artifact_store.py`
`tests/safety/test_stage5_boundaries.py`
`tests/safety/test_stage7_boundaries.py`

**Consumed interfaces.** Implement `Clock`, `IdentitySource` and
`CancellationToken` without modifying their contracts.
Supply `AuditEventIds` structurally and reuse `ThreadSafeCancellationToken`.
Preserve the existing six-member application `UnitOfWork`.

Sources:
`src/crypto_lab/domain/ports.py:37`,
`src/crypto_lab/domain/ports.py:53`,
`src/crypto_lab/domain/ports.py:79`,
`src/crypto_lab/audit/sink.py:23`,
`src/crypto_lab/process_supervision/cancellation.py:16`,
`src/crypto_lab/experiments/ports.py:244`.

**RED.**

1. `U1::test_runtime_clock_is_utc`: missing runtime implementation fails
   collection; subsequently require aware UTC wall time and valid monotonic values.
2. `U1::test_runtime_identities_validate`: missing identity implementation fails;
   every required identifier/token validates and draws occur only on request.
3. `U1::test_runtime_construction_is_explicit`: RED is missing-module failure.
   GREEN proof must reject planted import-time `datetime.now`, entropy draws,
   `ctypes.WinDLL` binding and signal registration.
4. `U1::test_dispatch_owner_contention_and_release`: missing ownership behavior
   fails; canonical aliases contend, distinct databases remain independent,
   and failure releases handles.
5. `U1::test_abandoned_owner_requires_reconciliation`: abandoned ownership
   cannot immediately authorize scheduling or PID-based adoption.
6. `U1::test_cancellation_bridge_is_scoped`: explicit installation requests
   idempotent cancellation and restores the previous handler on every exit.
7. `U1::test_storage_probe_refuses_unsupported_roots`: unsafe, remote, reparse,
   unsupported-filesystem and wrong-volume roots refuse before layout creation.
8. `tests/unit/experiments/test_application_ports.py::test_application_ports_are_inward_only`:
   missing ports fail; values remain detached and contain no concrete SQL,
   configuration, CLI or supervision types.
9. `tests/safety/test_stage5_boundaries.py::test_no_source_module_reads_an_ambient_clock_or_the_environment`:
   after the minimal runtime read is introduced, the existing unmodified scanner
   must reject it before the narrow exemption is added.
10. `tests/safety/test_stage5_boundaries.py::test_each_ambient_clock_exemption_licenses_exactly_its_pair`:
    initially fail because the exemption hook is absent.
    Require the real licensed read, alias equivalence and every reviewed near miss.
11. `S10::test_runtime_roots_are_module_scoped`: initially fail because the new
    confinement contract is absent; planted sibling imports/calls must fail after GREEN.
12. `S10::test_application_ports_are_inward_only`: the new guard must reject
    planted concrete infrastructure imports using the same scan as the real tree.

The fresh-import planted-control pattern is at
`tests/unit/test_package_layout.py:376`.
The ambient scanner and whole-block exemption pattern are at
`tests/safety/test_stage5_boundaries.py:233` and
`tests/safety/test_stage5_boundaries.py:575`.

**GREEN.**

1. Implement call-time UTC/monotonic clocks, entropy-backed UUID4 identities
   and existing-format temporary tokens; inject deterministic unit doubles.
2. Bind required kernel32 functions in `cli/runtime.py` itself, at call time.
   Do not expand or assume mutex/volume functions in the existing Windows API module.
3. Implement named-mutex ownership keyed by canonical database identity.
   Report contention and abandonment; close handles in `finally`.
4. Implement scoped signal-to-cancellation wiring using the existing cancellation type.
5. Probe explicit local roots without discovering alternatives.
   Preserve physical identity, NTFS and same-volume requirements.
6. Define narrow structural ports with immutable detached values.
   Keep concrete persistence, configuration, supervision and CLI types outside them.
   Application ports reach neither artifacts nor audit.
7. Add exactly:

   ```text
   _AMBIENT_CLOCK_EXEMPTIONS ==
   frozenset({("cli/runtime.py", "datetime.datetime.now")})
   ```

8. Preserve environment scanning unchanged.
   Reject `utcnow` and `date.today` in runtime, `now` in main and planted
   `cli/probe.py`, equivalent aliases and all import-time draws.

**Guard reconciliation.**

Reconcile these nine census owners in every introducing task T1-T5:

| Guard owner | Base source |
|---|---|
| Stage 3 source/root inventories | `tests/safety/test_stage3_boundaries.py:432` |
| Dotted package inventory | `tests/unit/test_package_layout.py:12` |
| Stage 8 census | `tests/safety/test_stage8_boundaries.py:1054` |
| Stage 9 arithmetic/root pins | `tests/safety/test_stage9_boundaries.py:496` |
| Database cross-pins | `tests/unit/persistence/test_sqlite_database.py:1806` |
| Migration cross-pins | `tests/unit/persistence/test_sqlite_migrations.py:1039` |
| Preflight cross-pins | `tests/unit/process_supervision/test_supervisor_preflight.py:1242` |
| Restart cross-pins | `tests/unit/process_supervision/test_restart_reconciliation.py:1754` |
| Store cross-pins | `tests/unit/artifacts/test_artifact_store.py:2047` |

For T1:

- Source/package census 135 -> 137; cumulative Stage 10 additions 0 -> 2.
  Append dotted names outside every pinned historical slice.
- Root census 30 -> 33, adding only time/secrets/signal.
  Stage 3 exact equality and all scalar/text mirrors advance together.
- Infrastructure pairs 17 -> 19 in
  `tests/safety/test_stage5_boundaries.py` and
  `tests/unit/persistence/test_sqlite_migrations.py`.
  Add only runtime/time and runtime/secrets.
- Stage 8 persistence-pair arithmetic `+ 1` -> `+ 3` at
  `tests/safety/test_stage8_boundaries.py:901`.
  SQLAlchemy/Alembic importers remain 12 -> 12 / 4 -> 4.
- Ambient-clock exemptions 0 -> 1 exact pair in
  `tests/safety/test_stage5_boundaries.py`.
  Preserve both clock-shape tests and the injected-clock controls.
- ctypes importers 1 -> 2 in
  `tests/safety/test_stage7_boundaries.py:147`, adding runtime only.
  asyncio/threading/queue/subprocess memberships remain unchanged.
- Advance quoted preflight/restart strings in
  `tests/unit/persistence/test_sqlite_database.py:1856` and
  `tests/unit/persistence/test_sqlite_migrations.py:1056`;
  preserve negative `== 95` and `== 27` pins.
- In `tests/safety/test_stage9_boundaries.py`, subtract the separate Stage 10 set;
  preserve Stage 9's 25-file set, Stage 8's 15-file set and historical remainder 51.
- Preserve `types` confinement to strategy/models.py::MappingProxyType,
  os confinement to artifacts/store.py::fstat/fsync and all cwd/home/expanduser denials.
  No new io/random/msvcrt/logging/tempfile/shutil/subprocess/queue/threading importer.
- Nominal schemas/hash profiles/actions/tables remain 48/20/25/21.
  Deferred names/readers/raw-token carriers/subprocess importers remain 13/5/4/13.
  D14 refreshes nominal pins after external corrections.

**Focused verification.**

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/unit/cli/test_runtime.py tests/unit/experiments/test_application_ports.py tests/unit/test_package_layout.py -q
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/safety/test_stage10_boundaries.py tests/safety/test_stage3_boundaries.py tests/safety/test_stage5_boundaries.py tests/safety/test_stage6_boundaries.py tests/safety/test_stage7_boundaries.py tests/safety/test_stage8_boundaries.py tests/safety/test_stage9_boundaries.py tests/architecture/test_package_import_boundaries.py tests/unit/persistence/test_sqlite_database.py tests/unit/persistence/test_sqlite_migrations.py tests/unit/process_supervision/test_supervisor_preflight.py tests/unit/process_supervision/test_restart_reconciliation.py tests/unit/artifacts/test_artifact_store.py -q
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-format-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-check-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 mypy-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 schema-generate-check
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 migration-check
```

**Review evidence.** Exact manifest/diff, intended RED failures, planted controls,
GREEN outputs, census arithmetic, call-time initialization, mutex identity/release,
scoped cancellation and inward ports.
Actual cross-process owner-death proof remains assigned to T7.
Attach complete operator verification for the reviewed subject.

**Section 33 criteria closed.**
33.1/1,3; 33.2/2,4-5,9; 33.4/6,12; 33.5/3,8; 33.6/1; 33.7/1-3.

**Decision-register items applied.**
D03,D04,D05,D06,D09,D10,D13,D14, under section 1.3.

T1's acceptance subject is exactly the untagged selectors plus the refusal paths.

**Commit message.** `feat: add local cli runtime services and application ports`

### Task 2 - Startup integrity, reconciliation ordering and scheduling barrier

**Objective.** Implement Matrix B's ordered startup under exclusive ownership,
detached durable queries, phased artifact recovery and the scheduling barrier.
Separate normal opening from explicit maintenance.

**Prerequisites.** Accepted T1 and current controller bindings.
Inject requeue assessment through T1's port.
A missing assessment or failed phase cannot produce a scheduling permit.
Unsupported required application mutations remain B2-blocked.

**Interfaces produced.**
`cli/startup.py::open_current_database`,
`cli/startup.py::check_database`,
`cli/startup.py::check_schema_distribution`,
`cli/startup.py::check_storage`,
`cli/startup.py::begin_reconciliation`,
`cli/startup.py::inventory_work`,
`cli/startup.py::reconcile_startup`,
`cli/startup.py::reconcile_runs`,
`cli/startup.py::permit_scheduling`;
detached startup-query projections;
`reconcile_finalization(..., phase="inventory"|"recover"|"sweep")`.

**Files created.**
`src/crypto_lab/cli/startup.py`
`tests/unit/cli/test_startup.py`
`tests/unit/persistence/test_sqlite_startup_queries.py`

**Files modified.**
`src/crypto_lab/persistence/database.py`
`src/crypto_lab/persistence/reconciliation_source.py`
`src/crypto_lab/artifacts/recovery.py`
`tests/unit/artifacts/test_artifact_recovery.py`
`tests/unit/persistence/test_sqlite_reconciliation_source.py`
`tests/safety/test_stage10_boundaries.py`
`tests/safety/test_stage3_boundaries.py`
`tests/safety/test_stage8_boundaries.py`
`tests/safety/test_stage9_boundaries.py`
`tests/unit/test_package_layout.py`
`tests/unit/persistence/test_sqlite_database.py`
`tests/unit/persistence/test_sqlite_migrations.py`
`tests/unit/process_supervision/test_supervisor_preflight.py`
`tests/unit/process_supervision/test_restart_reconciliation.py`
`tests/unit/artifacts/test_artifact_store.py`

**Consumed interfaces.** Use normal `open_database`, maintenance
`open_for_migration`, `apply_migrations`, consistency reporting and the public
artifact reconciler.
The normal opener refuses an absent database.
The maintenance opener admits EMPTY/BEHIND/CURRENT; migration execution itself
admits EMPTY/BEHIND.

Sources:
`src/crypto_lab/persistence/migration_runner.py:227`,
`src/crypto_lab/persistence/migration_runner.py:254`,
`src/crypto_lab/persistence/migration_runner.py:318`,
`src/crypto_lab/persistence/database.py:657`,
`src/crypto_lab/artifacts/recovery.py:1408`.

**RED.**

1. `U2::test_normal_startup_never_migrates`: missing startup module fails;
   absent/behind/foreign/unknown/unversioned databases must refuse without creation,
   stamping or upgrade.
2. `U2::test_database_gate`: exercise every integrity query and all twelve fields.
   Query failures and corruption refuse.
   `journal_open`/`unmapped_finalizing` enter fenced inventory.
3. `U2::test_schema_distribution_matches_registry`: the new checker must reject
   missing, extra, altered or unsafe entries at the explicitly supplied source root.
4. `U2::test_startup_phases_precede_scheduling`: require inventory -> invocations
   -> related runs -> purpose recovery -> requeue assessment -> orphan sweep.
5. `U2::test_failed_phase_never_permits_scheduling`: every required failure gives
   zero dispatch calls, bounded resource closure and ownership release.
6. `U2::test_reconciliation_phase_releases_before_dispatch`: release the nested
   reconciliation phase before scheduling while retaining dispatch ownership.
7. `tests/unit/artifacts/test_artifact_recovery.py::test_artifact_phase_selector_is_closed`:
   the existing signature first rejects the new keyword.
   Unknown values must later refuse before work.
8. `tests/unit/artifacts/test_artifact_recovery.py::test_inventory_never_promotes_results_or_sweeps_orphans`:
   inventory preserves active leases, registered mappings and unresolved RESULT bytes.
9. `tests/unit/artifacts/test_artifact_recovery.py::test_recover_follows_process_and_run_reconciliation`:
   recovery rereads authority and rejects a live child or missing captured exit.
10. `tests/unit/artifacts/test_artifact_recovery.py::test_unexpired_journal_remains_deferred`:
    exercise the selected-phase interface; a new dispatch owner supplies no takeover authority.
11. `tests/unit/persistence/test_sqlite_startup_queries.py::test_startup_queries_are_complete_detached_and_fail_closed`:
    missing query interfaces fail; malformed/read-failed populations cannot become empty success.
12. `tests/unit/persistence/test_sqlite_startup_queries.py::test_startup_queries_survive_reopen`:
    reconstruct identical detached facts over fresh connections.
13. `tests/unit/artifacts/test_artifact_recovery.py::test_selected_phase_summary_has_only_the_bounded_phase_addition`:
    selected phases retain count meanings and add only the bounded `phase` detail.
14. `U2::test_reconciliation_second_pass_is_idempotent`: supported recovery creates
    no duplicate attempt/ref/manifest/terminal transition; distinguish summary audits.
15. `U2::test_required_startup_audit_unavailable_refuses_mutation`: require refusal
    before unsupported migration/process/run mutation or launch.
16. `U2::test_startup_application_facts_are_atomic`
    (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch).
    This is the successful required-application-audit facet, not the refusal control.

For new negative-property seams, retain missing-module RED and a planted bypass
that the completed guard rejects.

**GREEN.**

1. Implement explicit scoped startup dependencies and the Matrix B trace.
   Revalidate mutable authority after owner acquisition.
2. Add complete detached projections in the two existing persistence query modules.
   Keep transactions short and outside process, hashing and filesystem work.
3. Add the optional keyword-only closed phase selector to the public reconciler.
   Omission preserves the complete pass.
   Do not call private recovery methods from CLI composition.
4. Selected phases return the existing report type with unchanged count meanings.
   Append the existing `RECONCILIATION_FINALIZATION_RESUMED` summary action with
   one additional bounded detail key, `phase`.
   The omitted-selector pass retains its unchanged detail set.
5. Inventory before invocation/run reconciliation.
   Perform RESULT recovery only after every 29.3 gate.
   Recover eligible EVIDENCE independently under 29.4.
6. Assess requeue eligibility without launching, then sweep orphans.
   Protect active leases and original deadlines.
7. Recheck all consistency queries after recovery.
   Fence unresolved affected work; unreadable or contradictory authority refuses.
8. Return an invocation-scoped scheduling permit tied to successful checks and owner.
   Rebuild it after restart.
9. For maintenance, return CURRENT replay before `apply_migrations`.
   Expose no migration-script override and never initialize during normal startup.
10. Check B2 capability before any unsupported maintenance/reconciliation mutation.

Existing complete-pass order, lease treatment, report and summary are at
`src/crypto_lab/artifacts/recovery.py:411`,
`src/crypto_lab/artifacts/recovery.py:451`,
`src/crypto_lab/artifacts/recovery.py:215`,
`src/crypto_lab/artifacts/recovery.py:1305`.

The twelve consistency fields are at
`src/crypto_lab/persistence/database.py:357`.

**Guard reconciliation.**

- Source/package census 137 -> 138; cumulative Stage 10 set 2 -> 3.
  Advance all nine T1-listed census owners and their quoted mirrors.
- Roots/pairs remain 33 -> 33 / 19 -> 19.
  Preserve every positional slice and historical subtraction.
- In `tests/safety/test_stage8_boundaries.py:201`,
  `tests/safety/test_stage8_boundaries.py:417` and
  `tests/safety/test_stage8_boundaries.py:904`, admit application_ports alongside
  experiments.ports in the two extended query modules only.
  Permitted application port families 1 -> 2.
- Separately reconcile the Stage 8 persistence-direction loop at
  `tests/safety/test_stage8_boundaries.py:940`.
  Exact named non-persistence importers 0 -> 1: `cli/startup.py`.
  Require equality with actual imports.
  T5 later adds composition; execution is added only if its actual implementation
  imports persistence.
- Every other non-CLI package remains denied.
  Add a planted `experiments/probe.py` persistence import that fails the same
  direction checker used by the real-tree guard.
- SQLAlchemy/Alembic importer counts remain 12 -> 12 / 4 -> 4.
  Persistence-only forbidden-root scans remain scoped and unchanged.
- Preserve all twelve consistency fields.
  No table, schema, migration or complete-pass detail change.
- In `tests/unit/artifacts/test_artifact_recovery.py`, pin both summary shapes:
  default details unchanged; selected-phase details plus exactly `phase`.
- Preserve all T1 root, clock, token and import controls.

The carve-out implements the specified CLI -> Persistence direction:
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:215`.

**Focused verification.**

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/unit/cli/test_startup.py tests/unit/persistence/test_sqlite_startup_queries.py tests/unit/persistence/test_sqlite_reconciliation_source.py tests/unit/artifacts/test_artifact_recovery.py tests/integration/persistence/test_sqlite_restart_reconciliation.py -q
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/safety/test_stage10_boundaries.py tests/safety/test_stage3_boundaries.py tests/safety/test_stage5_boundaries.py tests/safety/test_stage6_boundaries.py tests/safety/test_stage7_boundaries.py tests/safety/test_stage8_boundaries.py tests/safety/test_stage9_boundaries.py tests/architecture/test_package_import_boundaries.py tests/unit/test_package_layout.py tests/unit/persistence/test_sqlite_database.py tests/unit/persistence/test_sqlite_migrations.py tests/unit/process_supervision/test_supervisor_preflight.py tests/unit/process_supervision/test_restart_reconciliation.py tests/unit/artifacts/test_artifact_store.py -q
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-format-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-check-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 mypy-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 schema-generate-check
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 migration-check
```

**Review evidence.** Ordered phase trace, gate-failure matrix, detached/reopened
query snapshots, all twelve consistency classifications, active-lease cases,
default/selected summary details and persistence-direction planted control.
Require no premature promotion/sweep, no reconstructed exit and no transaction
spanning external work.
Attach same-subject complete operator verification.

**Section 33 criteria closed.**
33.1/3-4,6; 33.2/1-2,6-7,9; 33.4/6-12; 33.5/1,3-6,8-10;
33.6/1-9,11; 33.7/1-3.

**Decision-register items applied.**
D04,D05,D07,D08,D09,D10,D13,D14.
D08 does not establish missing durable facts or close B3.

T2's acceptance subject is exactly the untagged selectors plus the refusal paths.

**Commit message.** `feat: compose ordered cli startup reconciliation before dispatch`

### Task 3 - Explicit input registration, queue freeze and application audit wiring

**Objective.** Coordinate explicit strategy, fixture-dataset and experiment inputs,
compatibility and immutable queue operations.
Provide transaction joining and owner-qualified input evidence.

**Prerequisites.** Accepted T1-T2.
D14 reinspection precedes dependent successful B2/B3 work.
Current bounded acceptance covers pure/structural behavior and refusal paths.
No skip, xfail, invented action or hidden durable store supplies a prerequisite.

**Interfaces produced.** By-value catalog-entry construction in
`experiments/application.py`; reader-contract and typed-input refusal seams;
registration/compatibility orchestration; transaction-joining facade;
configuration/spec freeze and replay seams.
Successful required-audit publication and durable creation/queue replay retain
the tags below.

**Files created.**
`src/crypto_lab/experiments/application.py`
`tests/unit/experiments/test_application_service.py`
`tests/unit/cli/test_input_boundaries.py`

**Files modified.**
`tests/safety/test_stage10_boundaries.py`
`tests/safety/test_stage5_boundaries.py`
`tests/architecture/test_package_import_boundaries.py`
`tests/safety/test_stage3_boundaries.py`
`tests/safety/test_stage8_boundaries.py`
`tests/safety/test_stage9_boundaries.py`
`tests/unit/test_package_layout.py`
`tests/unit/persistence/test_sqlite_database.py`
`tests/unit/persistence/test_sqlite_migrations.py`
`tests/unit/process_supervision/test_supervisor_preflight.py`
`tests/unit/process_supervision/test_restart_reconciliation.py`
`tests/unit/artifacts/test_artifact_store.py`

**Consumed interfaces.** Use static `StrategyLoader.load`,
static `CompatibilityResolver.resolve`, `dataset_metadata_hash`,
existing create/queue services and input snapshot evidence.

Sources:
`src/crypto_lab/strategy/loader.py:279`,
`src/crypto_lab/capabilities/resolver.py:303`,
`src/crypto_lab/datasets/hashing.py:53`,
`src/crypto_lab/experiments/experiment_service.py:264`,
`src/crypto_lab/experiments/experiment_service.py:440`,
`src/crypto_lab/experiments/finalization.py:1557`.

IB's subject is the reader-contract and typed-input refusal seam of
`experiments/application.py`, exercised with in-memory doubles.
T3 creates no concrete physical CLI reader.
T5 implements physical confinement.

**RED.**

1. `U3::test_registration_is_transactional`: missing application module fails;
   injected required-audit refusal must leave no registry mutation visible to
   an independent reader.
2. `U3::test_joined_service_commit_is_deferred`, successful required-audit
   publication facet
   (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch).
3. `U3::test_joined_service_failure_cannot_publish`: inner failure, lost CAS,
   outer failure and inner `finally` rollback cannot split one command's facts.
   Exercise refusal/transaction mechanics without unsupported production actions.
4. `U3::test_input_hashes_are_recomputed`: changed strategy/dataset/partition/draft
   bytes cannot retain a claimed identity.
5. `IB::test_explicit_inputs_reject_unknown_fields`: unknown, malformed,
   coercible financial and invalid UTC input refuses before mutation.
6. `U3::test_catalog_requires_explicit_identity`: malformed/missing/extra engine
   metadata and catalog construction failures yield `CONFIG.CATALOG_ENTRY_INVALID`.
7. `U3::test_descriptor_negotiation_agreement`: unsupported versions/vocabulary
   and descriptor/catalog/slot disagreement refuse.
   Pure agreement/refusal assertions are current; successful durable negotiation
   facts remain B2-gated.
8. `U3::test_all_compatibility_outcomes`: pure resolution preserves all four
   outcomes and approximation exclusions; runtime.live refuses before attempt creation.
9. `U3::test_queue_freezes_complete_snapshot`: current projection/refusal facet
   checks complete snapshot, audit/material hashes, retry and compatibility equality.
   The successful audit/queue-fact commit-together facet is
   (B2-gated | B3-gated: authored at the D14 reinspection after integration; not part of this dispatch).
10. `U3::test_queue_replay_and_conflict`
    (B2-gated | B3-gated: authored at the D14 reinspection after integration; not part of this dispatch).
11. `U3::test_creation_replay_uses_stored_creation_instant`
    (B2-gated | B3-gated: authored at the D14 reinspection after integration; not part of this dispatch).
12. `IB::test_dataset_confinement_precedes_open`: an injected reader refusing
    ancestor/reparse/hard-link/swap violations prevents application registration.
    This proves the contract, not physical filesystem implementation.
13. `U3::test_input_evidence_matches_owner_and_registry`: current qualified-input
    and refusal facets preserve owner/hash identity.
    The audit-derived SYSTEM facet is
    (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch).
14. `U3::test_required_application_audit_unavailable_refuses_mutation`: unsupported
    required vocabulary refuses before mutation and launch.
    A log or diagnostic projection cannot replace the audit.

Initial RED for new negative seams is missing-module collection failure.
After GREEN, planted permissive readers, premature commits and unsupported-audit
bypasses must fail their controls.

**GREEN.**

1. Orchestrate explicit bytes and typed values over ports.
   Keep physical reads/hashing outside database transactions.
2. Expose D02 construction over adapter name, adapter version, executable path,
   executable hash and a copied runtime metadata mapping.
   Import no configuration model/module.
3. Validate `runtime_metadata["engine_identity"]` as
   `crypto_lab.domain.experiment.EngineIdentity`, with exactly
   `engine_name` and `engine_version`.
   Remove the reserved key from the copied catalog metadata.
   Preserve the original complete configuration snapshot.
4. Build `AdapterCatalogEntry`.
   Missing/extra/malformed/conflicting identity, path incompatibility,
   metadata retyping or any catalog-construction failure produces
   `CONFIG.CATALOG_ENTRY_INVALID`.
   Infer no identity from filenames or discovery.
5. Implement a transaction-joining facade preserving existing service signatures
   and the six-member repository port.
   Defer inner commits, handle inner-finally rollback, doom failed joins and
   prevent partial publication on lost CAS.
6. Admit supported facts only.
   Refuse unavailable required audit capabilities before associated mutation.
7. After B2/B3 reinspection, freeze the complete snapshot, immutable spec,
   hashes and faithfully typed queue fact atomically.
   Capture the instant the QUEUED CAS stamps inside that transaction.
   Retain its association with the immutable queued spec.
8. After B2/B3 reinspection, look up correlated creation before drawing identity.
   Rebuild replay material at the stored creation instant and compare its named hash.
   Missing/contradictory durable evidence refuses.
9. Produce qualified STRATEGY/DATASET/EXPERIMENT evidence through the existing route.
   Keep staging/finalization outside the transaction and report failures explicitly.

Engine identity fields and catalog/configuration differences are at
`src/crypto_lab/domain/experiment.py:122`,
`src/crypto_lab/adapters/catalog.py:87`,
`src/crypto_lab/configuration/models.py:390`.

The service transaction driver, queue timestamp construction, creation request
and closed audit vocabulary are at
`src/crypto_lab/experiments/experiment_service.py:143`,
`src/crypto_lab/experiments/experiment_service.py:483`,
`src/crypto_lab/experiments/requests.py:123`,
`src/crypto_lab/audit/models.py:61`.

**Guard reconciliation.**

- Source/package census 138 -> 139; Stage 10 additions 3 -> 4.
  Advance the nine census owners, quoted mirrors and historical subtraction.
  Roots/pairs remain 33 -> 33 / 19 -> 19.
- `tests/safety/test_stage5_boundaries.py:148`:
  out-of-scope entries 5 -> 3, releasing strategy/datasets only.
- `tests/architecture/test_package_import_boundaries.py:117`:
  allowed application packages 6 -> 8, adding strategy/datasets only.
  Preserve persistence/configuration/CLI/process-supervision denial.
- Re-point the architecture planted control at
  `tests/architecture/test_package_import_boundaries.py:698`
  from strategy to process_supervision.
- Re-point both released-edge parameter rows at
  `tests/safety/test_stage5_boundaries.py:706` and
  `tests/safety/test_stage5_boundaries.py:714`
  to process_supervision import shapes.
  Preserve the self-test at
  `tests/safety/test_stage5_boundaries.py:719`
  and its absolute/relative shape coverage.
- `tests/safety/test_stage9_boundaries.py:153` and
  `tests/safety/test_stage9_boundaries.py:160`:
  permitted importers 3 -> 4; actual importers 2 -> 3.
  Add application to both sets.
- At `tests/safety/test_stage9_boundaries.py:549`, pin application -> artifacts/audit.
  Preserve finalization -> artifacts/audit and run_manifest -> artifacts.
  Application ports reach neither.
- Preserve experiments -> persistence denial, including T2's planted control.
  No new reader, causal traversal owner or raw-token carrier.
- Stage 6/7 guards are unchanged regression targets.
  Preserve nominal schema/action/hash/table/migration contracts pending D14.

**Focused verification.**

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/unit/experiments/test_application_service.py tests/unit/cli/test_input_boundaries.py tests/unit/configuration/test_loader.py tests/unit/configuration/test_snapshot.py tests/unit/experiments/test_experiment_service.py tests/unit/experiments/test_canonical_input_evidence.py -q
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/safety/test_stage10_boundaries.py tests/safety/test_stage3_boundaries.py tests/safety/test_stage5_boundaries.py tests/safety/test_stage6_boundaries.py tests/safety/test_stage7_boundaries.py tests/safety/test_stage8_boundaries.py tests/safety/test_stage9_boundaries.py tests/architecture/test_package_import_boundaries.py tests/unit/test_package_layout.py tests/unit/persistence/test_sqlite_database.py tests/unit/persistence/test_sqlite_migrations.py tests/unit/process_supervision/test_supervisor_preflight.py tests/unit/process_supervision/test_restart_reconciliation.py tests/unit/artifacts/test_artifact_store.py -q
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-format-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-check-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 mypy-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 schema-generate-check
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 migration-check
```

**Review evidence.** Independent-reader atomicity, refusal rollback,
inner-finally behavior, lost-CAS handling, strict inputs, D02 metadata consumption,
qualified owner evidence and all re-pointed controls.
Gated evidence later includes original/replayed spec bytes, original queue fact
and restart proof.
Complete operator verification must match the reviewed dispatch subject.

**Section 33 criteria closed.**
33.1/3-6; 33.2/2-3,5-9; 33.3/1-2,4-6,8; 33.4/1-11;
33.5/1-5; 33.6/1-5,7,11; 33.7/1-4.

**Decision-register items applied.**
D01,D02,D03,D05,D08,D09,D10,D13,D14.

T3's acceptance subject is exactly the untagged selectors plus the refusal paths.
Tagged successful publication/replay facets remain outside this dispatch.

**Commit message.** `feat: wire explicit cli inputs and immutable experiment queueing`

### Task 4 - Bounded scheduler and supervised command-to-finalization flow

**Objective.** Drive the ordered local queue with concurrency bounded to 1..8.
Compose command execution, conclusion, finalization, retry, cancellation and
aggregation through authoritative services and structural ports.

**Prerequisites.** Accepted T1-T3 and T2's scheduling-permit contract.
Successful concrete application mutations remain B2-gated.
Durable queue/restart ordering retains B3.
Use existing fake adapters only.

**Interfaces produced.**
`experiments/scheduler.py::recover_queue`,
`experiments/scheduler.py::drive`;
`cli/execution.py` implementation of T1's structural execution port,
including concrete outcome projection and bounded concurrent execution.

**Files created.**
`src/crypto_lab/experiments/scheduler.py`
`src/crypto_lab/cli/execution.py`
`tests/unit/experiments/test_scheduler.py`
`tests/unit/cli/test_execution.py`

**Files modified.**
`tests/safety/test_stage10_boundaries.py`
`tests/safety/test_stage7_boundaries.py`
`tests/safety/test_stage3_boundaries.py`
`tests/safety/test_stage8_boundaries.py`
`tests/safety/test_stage9_boundaries.py`
`tests/unit/test_package_layout.py`
`tests/unit/persistence/test_sqlite_database.py`
`tests/unit/persistence/test_sqlite_migrations.py`
`tests/unit/process_supervision/test_supervisor_preflight.py`
`tests/unit/process_supervision/test_restart_reconciliation.py`
`tests/unit/artifacts/test_artifact_store.py`

**Consumed interfaces.** Consume attempt/invocation services, retry evaluation,
due/successor operations, aggregation and conclusion routes.
Only the CLI bridge invokes/destructures concrete supervision outcomes.

Sources:
`src/crypto_lab/experiments/run_service.py:348`,
`src/crypto_lab/experiments/invocation_service.py:468`,
`src/crypto_lab/experiments/retry.py:513`,
`src/crypto_lab/experiments/retry.py:685`,
`src/crypto_lab/experiments/retry.py:698`,
`src/crypto_lab/experiments/aggregation.py:385`,
`src/crypto_lab/process_supervision/supervisor.py:365`,
`src/crypto_lab/experiments/finalization.py:3690`,
`src/crypto_lab/experiments/finalization.py:3973`.

**RED.**

1. `U4::test_startup_permit_is_required`: missing scheduler fails; missing/stale
   permits or failed assessment later produce zero claims/launches.
2. `U4::test_queue_order_uses_original_queue_fact`
   (B2-gated | B3-gated: authored at the D14 reinspection after integration; not part of this dispatch).
3. `U4::test_duplicate_claim_loses_before_launch`: structural CAS losers reread
   the winner and dispatch at most once.
4. `U4::test_concurrency_is_bounded_and_overlaps`: capacities 1,2,8 enforce limits;
   at capacity 2 both controlled executions enter before either is released.
5. `U5::test_only_supervisor_executes_commands`: concrete invocation occurs only
   through the injected supervisor; scheduler values remain structural.
6. `U5::test_launch_has_no_database_access`: command/request/root projection
   exposes no core database capability; no transaction spans execution.
7. `U4::test_validate_precedes_run`: excluded/unavailable/failed validation
   prevents RUN; DESCRIBE gets no fabricated run or token.
8. `U5::test_process_exit_category_preserved`: preserve all eight process categories
   independently of CLI exits.
9. `U5::test_non_exited_outcome_bypasses_conclusion_helpers`: non-EXITED outcomes
   cannot enter EXITED-only conclusion routes.
10. `U5::test_success_requires_registered_result_manifest`: zero exit or moved
    bytes alone cannot produce success.
11. `U5::test_non_success_has_no_result`: eligible EVIDENCE remains separate;
    failed result candidates cannot become evidence or results.
12. `U4::test_retry_gates`: structural policy cases enforce all six gates,
    hard blocks, attempt limits and fresh availability.
13. `U4::test_retry_delay_uses_durable_instant`, full audited scheduler/restart facet
    (B2-gated | B3-gated: authored at the D14 reinspection after integration; not part of this dispatch).
14. `U4::test_successor_has_fresh_material`: structural due/approval cases draw
    fresh IDs/token/roots exactly once and preserve predecessors.
15. `U4::test_cancel_finalization_and_aggregation_races`: structural CAS winners
    prevent reopening and successors; unsupported concrete cancellation refuses.
16. `U4::test_aggregate_preserves_slot_outcomes`: preserve success, warnings,
    partial success, incompatibility and unavailability without averaging.
17. `U5::test_request_material_lifetime_is_invocation_scoped`: release existing
    wrappers after permitted conclusion/cleanup; never reconstruct missing tokens.
18. `U5::test_trace_audit_refusal_blocks_associated_transition`: current refusal
    facet prevents unsupported mutation.
    Successful atomic application-audit publication is
    (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch).

New negative-property seams use missing-module RED plus planted violating GREEN controls.
Successful production workflow facets are not inferred from structural doubles.

**GREEN.**

1. Implement scheduler orchestration over inward query/transaction/execution ports.
   Keep asyncio and concrete supervision types outside experiments.
2. Own asyncio tasks/concurrent awaits in `cli/execution.py`.
   Keep capacity occupied through required conclusion; refill from fresh eligibility.
3. Require a fresh scheduling permit and durable CAS before dispatch.
   Refuse unsupported required audit mutation before claiming/launching.
4. Construct exact registered DESCRIBE/VALIDATE/RUN commands.
   Scope lifecycle/request material to one invocation and discard after bounded cleanup.
5. Project concrete outcomes into existing adapter/domain facts.
   Route DESCRIBE EXITED separately from VALIDATE/RUN EXITED.
6. Preserve actual non-EXITED winners and call independently eligible evidence
   operations explicitly.
   Do not manufacture captured exits or success.
7. Run blocking conclusion/filesystem work through the bridge's bounded async route,
   without retaining an open database transaction.
8. Delegate retry, due checks, successors and aggregation.
   After corrective admission, preserve original queue/not-before/deadline facts.
9. Implement requeue assessment without launching during reconciliation.
   Fence uncertain children, active journals and missing durable ordering facts.

Both conclusion helpers require EXITED:
`src/crypto_lab/experiments/finalization.py:3721`,
`src/crypto_lab/experiments/finalization.py:3999`.

Lifecycle construction, material retention and registration are at
`src/crypto_lab/experiments/supervision_lifecycle.py:346`,
`src/crypto_lab/experiments/supervision_lifecycle.py:352`,
`src/crypto_lab/experiments/supervision_lifecycle.py:354`.

**Guard reconciliation.**

- Source/package census 139 -> 141; Stage 10 additions 4 -> 6.
  Advance all nine census owners and their quoted mirrors.
- Roots/pairs remain 33 -> 33 / 19 -> 19.
- asyncio importers 1 -> 2 in
  `tests/safety/test_stage7_boundaries.py:147`, adding execution only.
- Stage 9 permitted importers 4 -> 5; actual importers 3 -> 4 in
  `tests/safety/test_stage9_boundaries.py:153` and
  `tests/safety/test_stage9_boundaries.py:160`.
  Scheduler reaches exactly audit.
- Preserve application -> artifacts/audit and application_ports -> neither.
  Preserve experiments -> persistence denial.
- If execution actually imports persistence, extend the exact CLI set in
  `tests/safety/test_stage8_boundaries.py:940` by 1 in this introducing task.
  Otherwise membership remains 1 -> 1.
  Preserve the planted experiments/probe.py failure.
- D06 releases no process-supervision edge in Stage 5 or architecture guards.
  Both remain unchanged regression targets.
- Preserve sole production Popen at
  `tests/safety/test_stage7_boundaries.py:624`,
  subprocess/threading/queue sets, four token carriers and five readers.
- Preserve schema/action/hash/migration and contract/fake inventories pending D14.

**Focused verification.**

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/unit/experiments/test_scheduler.py tests/unit/cli/test_execution.py tests/unit/experiments/test_retry_decision.py tests/unit/experiments/test_successor_creation.py tests/unit/experiments/test_aggregation.py tests/unit/experiments/test_semantic_outcome.py tests/unit/experiments/test_finalization_service.py tests/unit/experiments/test_cancellation_races.py -q
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/safety/test_stage10_boundaries.py tests/safety/test_stage3_boundaries.py tests/safety/test_stage5_boundaries.py tests/safety/test_stage6_boundaries.py tests/safety/test_stage7_boundaries.py tests/safety/test_stage8_boundaries.py tests/safety/test_stage9_boundaries.py tests/architecture/test_package_import_boundaries.py tests/unit/test_package_layout.py tests/unit/persistence/test_sqlite_database.py tests/unit/persistence/test_sqlite_migrations.py tests/unit/process_supervision/test_supervisor_preflight.py tests/unit/process_supervision/test_restart_reconciliation.py tests/unit/artifacts/test_artifact_store.py -q
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-format-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-check-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 mypy-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 schema-generate-check
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 migration-check
```

**Review evidence.** Controlled overlap, capacity maxima, CAS losers,
transaction lifetimes, exact argv, concrete outcome destructuring, non-EXITED
branches, RESULT/EVIDENCE queries and invocation-scoped material release.
Gated evidence later includes durable ordering/retry and atomic application audits.
Attach same-subject complete operator verification.

**Section 33 criteria closed.**
33.1/3-6; 33.2/5; 33.3/4-6; 33.4/1-11; 33.5/1-5,7-9;
33.6/2-8,10-11; 33.7/1,3.

**Decision-register items applied.**
D01,D03,D04,D05,D06,D07,D08,D09,D10,D13,D14.

T4's acceptance subject is exactly the untagged selectors plus the refusal paths.

**Commit message.** `feat: drive bounded cli experiments through supervision and finalization`

### Task 5 - Operational CLI, concrete composition and closed command contract

**Objective.** Implement Matrix A's grammar, concrete wiring, confined readers,
safe projections and deterministic CLI exits.
Provide the concrete reviewed grammar consumed by P1.

**Prerequisites.** Accepted T1-T4.
P1 follows this grammar and closes before T6 dispatch.
Successful concrete mutations remain B2-gated; correlated creation/queue replay
also retains B3.
The launcher amendment remains outside this worker.

**Interfaces produced.**
`cli/main.py::build_parser` extended;
`cli/main.py::main`;
`cli/composition.py::load_inputs`,
`cli/composition.py::open_resources`,
`cli/composition.py::close`;
`cli/commands.py::parse_command` and typed operational command set;
`cli/reporting.py` bounded text/JSON projection functions.

**Files created.**
`src/crypto_lab/cli/composition.py`
`src/crypto_lab/cli/commands.py`
`src/crypto_lab/cli/reporting.py`
`tests/unit/cli/test_composition.py`
`tests/unit/cli/test_commands.py`
`tests/unit/cli/test_reporting.py`

**Files modified.**
`src/crypto_lab/cli/main.py`
`tests/unit/test_cli.py`
`tests/safety/test_stage10_boundaries.py`
`tests/safety/test_stage3_boundaries.py`
`tests/safety/test_stage8_boundaries.py`
`tests/safety/test_stage9_boundaries.py`
`tests/unit/test_package_layout.py`
`tests/unit/persistence/test_sqlite_database.py`
`tests/unit/persistence/test_sqlite_migrations.py`
`tests/unit/process_supervision/test_supervisor_preflight.py`
`tests/unit/process_supervision/test_restart_reconciliation.py`
`tests/unit/artifacts/test_artifact_store.py`

**Consumed interfaces.** Preserve `build_parser()` and `main(argv=None) -> int`,
the console target and accepted T1-T4 contracts.
Use explicit configuration loading/snapshots, existing catalog, comparison and
single-entry quarantine purge.

Sources:
`src/crypto_lab/cli/main.py:12`,
`src/crypto_lab/cli/main.py:26`,
`pyproject.toml:19`,
`src/crypto_lab/configuration/loader.py:141`,
`src/crypto_lab/configuration/snapshot.py:92`,
`src/crypto_lab/adapters/catalog.py:87`,
`src/crypto_lab/experiments/comparison.py:136`,
`src/crypto_lab/artifacts/recovery.py:1445`.

**RED.**

1. `U6::test_operational_grammar_is_closed`: new command module is missing;
   require every Matrix A command and reject duplicates/surplus/unknown/malformed input.
2. `UC::test_help_and_version_construct_no_runtime`: RED is missing-module failure.
   GREEN proof rejects a planted eager clock/entropy/database-open control.
3. `tests/unit/test_cli.py::test_unknown_argument_nonmatching_control_is_not_echoed`:
   existing argparse behavior first echoes unsafe supplied tokens.
   Require bounded placeholder/count output instead.
4. `UC::test_composition_is_explicit_and_lazy`: RED is missing-module failure.
   GREEN proof rejects planted eager initialization and implicit base discovery.
5. `UC::test_catalog_metadata_identity_is_validated`: composition must project
   T3's stable refusal and enforce descriptor/slot agreement.
6. `UC::test_input_reader_checks_physical_identity`: bounded physical reads reject
   ancestor/reparse/hard-link/swap escapes before registration.
7. `U6::test_commands_preserve_maintenance_and_control_routes`: separate maintenance,
   reconciliation, read-only query and bounded cancellation routes.
8. `U7::test_reporting_preserves_outcomes_and_purposes`: exact Matrix A exits,
   aggregate tie-breaks and distinct RESULT/EVIDENCE labels.
9. `U7::test_projection_never_dumps_untrusted_material`: source documents,
   tokens/control bytes and mutable exception dumps cannot reach projections.
10. `U7::test_approximation_reasons_survive_projection`,
    `U7::test_diagnostic_projection` and `U6::test_comparison_command`:
    new projection/command seams fail until implemented.
11. `UC::test_required_audit_capability_refuses_before_mutation`: unsupported
    create/validate/queue/run/cancel/maintenance facts refuse before mutation/launch.
12. `UC::test_concrete_mutations_and_audit_projections`
    (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch).
13. `UC::test_correlated_creation_and_queue_replay`
    (B2-gated | B3-gated: authored at the D14 reinspection after integration; not part of this dispatch).

Preserve the already-green harmless regression
`tests/unit/test_cli.py::test_unknown_argument_uses_argparse_error`.
It is a regression target, not a claimed new RED.

**GREEN.**

1. Implement typed internal commands and closed subparsers.
   Require explicit operational invocation base/correlation.
   Preserve help/version and `SystemExit(2)` conventions.
2. Echo unknown options only when they match
   `^--?[A-Za-z0-9][A-Za-z0-9-]{0,63}$`.
   Otherwise print bounded placeholder/count output.
   Apply equivalent protection to other parser errors that could echo values.
3. Construct resources at call time and close in `finally`.
   Keep read queries non-dispatching; cancellation never reconciles or launches.
4. Implement the concrete physically confined strategy/dataset readers.
   Apply bounded reads and physical identity/swap checks outside transactions.
5. Pass adapter name/version, executable path/hash and copied runtime metadata
   by value to T3's catalog-entry construction.
   T3 validates `EngineIdentity`, removes the reserved key and produces
   `CONFIG.CATALOG_ENTRY_INVALID`.
   T5 projects the refusal and verifies descriptor/slot agreement.
6. Derive exactly `invocation_base / "schemas"` and pass it to T2's checker.
   Expose no schema-location option or discovery fallback.
7. Project identical sanitized facts in bounded text/JSON.
   Preserve query exit 0 independently of the queried execution state.
8. Deliver exact grammar/argv examples to P1.
   P1 alone admits absolute drive-letter path tokens, preserves each as one
   argument and implements its reviewed closed validator.
9. Keep unsupported required mutations refused until corrective admission.
   No parser branch bypasses B2 through logging.

The existing harmless parser assertion is at
`tests/unit/test_cli.py:68`.
Source/wheel schema placement differs at
`pyproject.toml:40` and `pyproject.toml:42`.

**Guard reconciliation.**

- Source/package census 141 -> 144; Stage 10 additions 6 -> 9.
  Advance all nine census owners, quoted mirrors and subtraction operands.
- Roots 33 -> 34, adding sys only in cli/main.py.
  Infrastructure pairs 19 -> 19; ambient exemption 1 -> 1.
- Extend T2's persistence-direction set in
  `tests/safety/test_stage8_boundaries.py:940` with cli/composition.py.
  Startup/composition membership is 1 -> 2 if execution imports no persistence,
  or 2 -> 3 if execution was already admitted.
  Include execution only if actual.
  Every other package stays denied; planted experiments/probe.py still fails.
- Preserve the exact ambient constant and
  `tests/safety/test_stage5_boundaries.py::test_each_ambient_clock_exemption_licenses_exactly_its_pair`.
  Main gets no clock/environment exemption.
- Product operations remain 21 -> 21 in T5; P1 alone advances 21 -> 22.
  Worker profiles remain 6 -> 6.
  Verifier profiles/steps remain 10 -> 10 / 11 -> 11.
- Preserve nominal schemas/hash profiles/actions/tables 48/20/25/21.
  Released definitions are pinned at
  `tests/safety/test_stage9_boundaries.py:639`,
  hash profiles at `tests/safety/test_stage9_boundaries.py:651`,
  actions at `tests/safety/test_stage9_boundaries.py:707`,
  deferred names at `tests/safety/test_stage3_boundaries.py:207`.
- Preserve `types`, os, importlib, cwd/home/expanduser and subprocess confinement.
  CLI importlib use is metadata/resources only.
  D14 reinspects external corrective changes.

**Focused verification.**

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/unit/test_cli.py tests/unit/cli/test_composition.py tests/unit/cli/test_commands.py tests/unit/cli/test_reporting.py tests/unit/cli/test_input_boundaries.py -q
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/safety/test_stage10_boundaries.py tests/safety/test_stage3_boundaries.py tests/safety/test_stage5_boundaries.py tests/safety/test_stage6_boundaries.py tests/safety/test_stage7_boundaries.py tests/safety/test_stage8_boundaries.py tests/safety/test_stage9_boundaries.py tests/architecture tests/unit/test_package_layout.py tests/unit/persistence/test_sqlite_database.py tests/unit/persistence/test_sqlite_migrations.py tests/unit/process_supervision/test_supervisor_preflight.py tests/unit/process_supervision/test_restart_reconciliation.py tests/unit/artifacts/test_artifact_store.py tests/safety/test_uv_launcher.py -q
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-format-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-check-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 mypy-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 schema-generate-check
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 migration-check
```

**Review evidence.** Command branches, safe/unsafe echo controls, planted eager
controls, physical reads, T3 catalog delegation, purpose labels, exits and
persistence-direction membership.
P1 separately supplies its patch, raw/normalized hashes, review, human commit
and old-byte refusal/new-byte hook acceptance before T6.
Attach same-subject complete operator verification.

**Section 33 criteria closed.**
33.1/1,3-6; 33.2/2-3,5-9; 33.3/1-2,4-8; 33.4/1-12;
33.5/1-6,8,10; 33.6/1-8,10-11; 33.7/1-4.

**Decision-register items applied.**
D01-D11,D13,D14, using only section 1.3's registered classes.

T5's acceptance subject is exactly the untagged selectors plus the refusal paths.

**Commit message.** `feat: expose offline local commands through closed cli composition`

### Task 6 - Complete CLI outcome and boundary acceptance matrix

**Objective.** Exercise production composition using explicit fixtures and existing
fake adapters.
Implement the current refusal/scanner subject and retain the complete
post-prerequisite workflow obligations without claiming they execute on this base.

**Prerequisites.** Accepted T1-T5; P1 human commit, complete verification and
committed-byte hook re-pin.
Workers still use only the six admitted profiles.
D14 must admit each tagged success facet before authoring its dependent dispatch.

**Interfaces produced.** Launch-free fixture/argv/projection/snapshot/scan helpers
in `tests/cli_support.py`; W/X/TOK acceptance selectors; a separate CLI case ledger.
No production API or new process launcher.

**Files created.**
`tests/cli_support.py`
`tests/integration/cli/test_cli_workflows.py`
`tests/integration/cli/test_cli_boundaries.py`
`tests/integration/cli/test_cli_token_absence.py`

**Files modified.**
`tests/unit/test_cli.py`
`tests/safety/test_stage10_boundaries.py`

**Consumed interfaces.** Invoke production `crypto_lab.cli.main.main(argv)` and
accepted concrete composition.
Use existing fake scenarios, SQLite, supervisor, finalizer and registrar.
The existing exact-byte scanner control supplies a pattern, not the new oracle.

Sources:
`tests/integration/process_supervision/test_supervised_contract_matrix.py:214`,
`tests/integration/persistence/test_stage9_token_absence.py:197`.

**RED.**

1. For each admitted new W/X row, record collection RED because
   `tests/cli_support.py` and the W/X modules do not exist before this task.
   After GREEN, a planted wrong-outcome control, such as expected exit plus one,
   must fail.
   Tagged full rows below are authored only at their D14 reinspection.

| Matrix C | Exact selector | Post-prerequisite oracle | B2/B3 marker |
|---|---|---|---|
| C01 | `W::test_cli_success` | COMPLETED/SUCCEEDED; registered RESULT/core manifest; exit 0 | (B2-gated \| B3-gated: authored at the D14 reinspection after integration; not part of this dispatch) |
| C02 | `W::test_cli_warning` | Warning retained; no warning-only retry; exit 0 | (B2-gated \| B3-gated: authored at the D14 reinspection after integration; not part of this dispatch) |
| C03 | `W::test_cli_partial_success` | Every slot visible; RESULT only for success; exit 0 | (B2-gated \| B3-gated: authored at the D14 reinspection after integration; not part of this dispatch) |
| C04 | `W::test_cli_all_not_applicable` | Zero excluded-slot attempts; reasons; exit 5 | (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch) |
| C05 | `W::test_cli_late_not_applicable` | Captured exit 20; NOT_APPLICABLE; no RESULT; exit 5 | (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch) |
| C06 | `W::test_cli_preflight_unavailable` | Explicit missing runtime; no invented attempt; exit 6 | (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch) |
| C07 | `W::test_cli_attempt_unavailable` | Launch/exit-30 distinction; six retry gates; exit 6 | (B2-gated \| B3-gated: authored at the D14 reinspection after integration; not part of this dispatch) |
| C08 | `W::test_cli_crash` | Captured crash/diagnostic; no RESULT; exit 7 | (B2-gated \| B3-gated: authored at the D14 reinspection after integration; not part of this dispatch) |
| C09 | `X::test_cli_protocol_refusals` | Supervised identity/token/sequence/trust refusal; exit 8 | (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch) |
| C10 | `W::test_cli_deadlines` | Original core deadline winner; exit 9 | (B2-gated \| B3-gated: authored at the D14 reinspection after integration; not part of this dispatch) |
| C11 | `W::test_cli_finalization_timeout` | Invocation EXITED; run TIMED_OUT; no RESULT; exit 9 | (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch) |
| C12 | `W::test_cli_cancel` | Request exit 0; driver 130; durable winner/cleanup | (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch) |
| C19 | `X::test_cli_prelaunch_refusals` | No prohibited mutation/child; exit 2/3/4 | Current refusal subject; B2 remains enforced |
| C20 | `X::test_cli_artifact_refusals` | Full workflow integrity failure; no RESULT; exit 1 | (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch) |

B3 applies to the inherited creation/queue-order/retry facets described in Matrix C.
A row not separately tagged B3 still inherits any B3-dependent setup it actually uses.
An isolated supported artifact facet uses an explicitly planted durable prestate,
requires no unsupported preceding mutation and proves only that facet.

2. `X::test_cli_required_audit_unavailable_refuses_mutation`:
   parameterize every unsupported command mutation; expect exit 4,
   stable corrective diagnostic and unchanged durable/child state.
3. `X::test_cli_unknown_fields`, `X::test_cli_decimal_inputs`,
   `X::test_cli_strategy_input_boundary`, `X::test_cli_dataset_confinement`,
   `X::test_cli_material_override_conflict`,
   `X::test_cli_runtime_live_rejected_before_launch`:
   current input/refusal facets fail until the launch-free fixture route exists.
4. `X::test_cli_unknown_argument_nonmatching_control`:
   production-parser integration control distinct from T5's unit selector.
   Retain harmless `--unknown` as the matching comparison.
5. `TOK::test_cli_token_scan_positive_control`:
   independent scanning must find planted exact raw bytes and distinguish hashes,
   altered needles and split/noncontiguous bytes.
   A planted missed surface must fail.
6. `W::test_cli_non_success_has_no_result`
   (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch).
   Inspect refs, links and manifests; distinguish prior successes/input evidence.
7. `X::test_cli_event_replay_conflict`, `X::test_cli_adapter_write_boundary`,
   `X::test_cli_zero_exit_without_manifest`, `X::test_cli_manifest_membership`,
   `X::test_cli_evidence_roles`
   (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch).
   Their full supervised/application workflow facets require admitted setup.
8. `X::test_cli_comparison_exclusions`:
   immutable registered-manifest query/refusal facets are current.
   A planted prestate does not prove registration commands succeeded.
9. `W::test_cli_approximation` and `W::test_cli_input_and_system_evidence`,
   successful application/audit facets
   (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch).
10. `TOK::test_cli_run_and_validate_token_absence`
    (B2-gated | B3-gated: authored at the D14 reinspection after integration; not part of this dispatch).
    Require conformant token-bearing VALIDATE and RUN workflow roots,
    independently scanned after cleanup and before teardown.

**GREEN.**

1. Implement launch-free support for explicit temporary roots, closed argv,
   output capture and independent durable snapshots.
2. W/X/TOK normal rows call production `main(argv)` in-process.
   Do not import a test module as a support library.
3. Any T6 selector requiring a real CLI child lives in
   `tests/unit/test_cli.py`.
   That existing importer calls launch-free support helpers, never the reverse.
4. Real children use the reviewed test interpreter:

   ```text
   sys.executable -I -B -m crypto_lab.cli <closed Matrix A arguments>
   ```

   Use `shell=False`, bounded waits and a fresh literal child environment
   containing `PYDANTIC_DISABLE_PLUGINS=__all__` before startup.
   Inspect no ambient value.
   This environment construction is new reviewed test-launch behavior;
   the inherited helper has no `env=` argument at `tests/unit/test_cli.py:19`.

5. Tests never invoke `cli-local`.
   Its operational demonstration remains operator-run.
6. On this base, execute C19, supported read-only/refusal facets and independent
   scanner controls.
   Do not complete an unsupported mutation and defer only its audit assertion.
7. At D14-admitted dispatches, establish setup through production commands and
   assert every specification 28.3 facet: database, lifecycle history, audits,
   diagnostics, artifacts and child cleanup.
8. Cover adapter categories 0/10/20/30/40/50/60/70 independently of CLI exits.
   Self-reported cancel/timeout cannot invent a core winner.
9. Scan database bytes, present live WAL/SHM, serialized columns, logs,
   diagnostics, audits, projections, finalized objects/artifacts, staging,
   quarantine and every command root.
   Include conformant VALIDATE request/output roots and RUN roots.
10. Record absent optional sidecars explicitly.
    Unreadable required surfaces fail.
    Retain populated fixture roots through scanning; do not delete them first.
11. Keep C13-C18 assigned to T7's exact R/RC/RF hosts.
    Full C01-C20 acceptance remains incomplete until all required admitted rows pass.

Sources:
`src/crypto_lab/adapters/exit_codes.py:34`,
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2096`.

**Guard reconciliation.**

- Source/root/pair/profile counts remain
  144 -> 144 / 34 -> 34 / 19 -> 19 / 22 -> 22.
- Worker profiles/subprocess importers remain 6 -> 6 / 13 -> 13.
  Preserve the exact importer equality in
  `tests/safety/test_stage6_boundaries.py:372`.
- Token carriers/readers/fake roots remain 4 -> 4 / 5 -> 5 / 7 -> 7.
  Use existing token wrappers, with no new raw-token field carrier.
- Contract numbered rows/entries remain 52/58 -> 52/58;
  supervision/platform inventories remain 6/26 -> 6/26.
  Keep CLI inventory separate.
- Preserve nominal schema/action/hash/table contracts 48/25/20/21.
  No fake program, contract-manifest or historical schema edit.
- Stage 10 guard checks support remains launch-free and real-child selectors
  are hosted in the admitted importer.
  Preserve T2/T5 persistence-direction and all clock controls.

**Focused verification.**

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/integration/cli/test_cli_workflows.py tests/integration/cli/test_cli_boundaries.py tests/integration/cli/test_cli_token_absence.py tests/unit/test_cli.py tests/integration/process_supervision/test_supervised_contract_matrix.py -q
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/contract tests/integration/persistence tests/safety tests/architecture tests/unit/test_schema_registry.py -q
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-format-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-check-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 mypy-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 schema-generate-check
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 migration-check
```

**Review evidence.** Exact C-row/selector/marker map, current refusal snapshots,
wrong-outcome controls, independent scanner positive controls and real-child placement.
Later admitted evidence must show conformant token-bearing VALIDATE,
every visited surface and all six workflow assertion facets.
Retain B1 partial-evidence limits and B2/B3 blockers.
Attach same-subject complete operator verification.

**Section 33 criteria closed.**
33.1/4-6; 33.2/2-9; 33.3/1-2,4-8; 33.4/1-11;
33.5/1-5,7-10; 33.6/1-8,10-11; 33.7/1-3.

**Decision-register items applied.**
D01,D02,D05,D06,D08,D09,D10,D11,D13,D14.

T6's acceptance subject is exactly the untagged selectors plus the refusal paths.
Tagged workflow/audit facets are authored at D14 reinspection.

**Commit message.** `test: cover complete offline cli outcome and boundary matrix`

### Task 7 - CLI restart, killed-child recovery and honest cleanup evidence

**Objective.** Prove supported startup/recovery and the complete admitted
restart/crash matrix.
Observe survivors before cleanup and preserve retained-holder WAL discipline.

**Prerequisites.** Accepted T1-T6 and P1.
D14 admits full mutated resume/requeue/cancel/retry facets.
A live RUNNING PID-reuse failure returns to the Stage 7 corrective owner.
This test task does not expand into supervisor implementation.

**Interfaces produced.** In-process R recovery selectors; RC/RF real-child
selectors; launch-free recovery/snapshot/scan support; pre-cleanup survivor and
retained-holder ordering evidence.

**Files created.**
`tests/integration/cli/test_cli_recovery.py`

**Files modified.**
`tests/cli_support.py`
`tests/integration/artifacts/test_finalization_crash_child.py`
`tests/unit/test_cli.py`
`tests/safety/test_stage10_boundaries.py`

**Consumed interfaces.** Accepted startup, scheduler resume and projections.
Reuse the existing crash-child retained-handle discipline.
Launcher exit alone is not SQLite-holder exit.

Source:
`tests/integration/artifacts/test_finalization_crash_child.py:13`.

**RED.**

1. `R::test_cli_startup_barrier`: missing recovery module/support fails;
   gate failures/owner contention must yield zero launches.
   Full audited resumed scheduling is
   (B2-gated | B3-gated: authored at the D14 reinspection after integration; not part of this dispatch).
2. `R::test_cli_cancel_finalization_races` for C13
   (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch).
3. `R::test_cli_stale_attempt` for C14
   (B2-gated | B3-gated: authored at the D14 reinspection after integration; not part of this dispatch).
4. `R::test_cli_recover_captured_result` for C15:
   current independently supported artifact-only facet uses a declared planted
   prestate and all 29.3 gates.
   The complete resume/aggregate facet is
   (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch).
5. `R::test_cli_lost_exit` for C16:
   current read-only/refusal facet cannot infer EXITED or success.
   Unsupported transition/conclusion facets are
   (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch).
6. `RC::test_cli_killed_child` for C17:
   current child/owner refusal controls retain exact process identity.
   Full mutated recovery/requeue is
   (B2-gated | B3-gated: authored at the D14 reinspection after integration; not part of this dispatch).
7. `RF::test_cli_finalization_crash_points` for C18:
   supported artifact-only crash cells proceed independently.
   Full production setup/resume facets are
   (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch).
8. `R::test_cli_deadline_survives_restart`:
   preserved-fact/refusal assertions are current.
   Full unsupported application transition facets are
   (B2-gated: authored at the D14 reinspection after integration; not part of this dispatch).
9. `R::test_cli_retry_delay_survives_restart` and `R::test_cli_retry_after_restart`
   (B2-gated | B3-gated: authored at the D14 reinspection after integration; not part of this dispatch).
10. `R::test_cli_recovery_second_pass_is_idempotent`:
    current supported artifact replay creates no duplicate ref/manifest/change.
    Full mutated resume/requeue is
    (B2-gated | B3-gated: authored at the D14 reinspection after integration; not part of this dispatch).
11. `RC::test_cli_survivor_observation_precedes_cleanup`:
    initial new control fails until observation is separated from termination.
    A planted matching live child fails the leak oracle even if cleanup succeeds.
12. `RF::test_cli_wal_first_opener_waits_for_real_holder_exit`:
    deliberately inverted ordering must fail;
    reopening waits for verified actual-interpreter/descendant termination.
13. `RC::test_cli_live_running_pid_reuse_is_not_adopted`:
    mismatched creation identity authorizes neither adoption nor termination.
14. `TOK::test_cli_run_and_validate_token_absence`, after full crash/retry workflow
    (B2-gated | B3-gated: authored at the D14 reinspection after integration; not part of this dispatch).
    Current supported scans still reject unreadable required surfaces and use
    T6's independent positive control.

New module negatives use missing-module RED plus planted violating GREEN proof.
Existing regression passes are not relabelled RED.

**GREEN.**

1. Keep R in-process only.
   RC is `tests/unit/test_cli.py`;
   RF is `tests/integration/artifacts/test_finalization_crash_child.py`.
   Only those existing importers host real CLI child selectors.
2. The importers call launch-free `tests/cli_support.py` helpers.
   Never reverse that dependency or import a test module as a library.
3. Observe matching live children and durable creation identities without killing.
   Freeze that set for leak assertions.
   Then perform bounded identity-verified cleanup in `finally`.
4. Retain actual interpreter/verified-descendant handles while alive.
   Recheck identity, terminate and await through those handles,
   inspect native exit, reap the launcher separately, prove descendant exit,
   and only then reopen SQLite.
5. Retain Matrix B order and per-phase fresh authority.
   Preserve unexpired leases and fence unresolved work.
6. Include a negative control for every 29.3 RESULT gate.
   Lost exit alone cannot become EXITED/success.
   Treat independent stdout-trust loss separately.
7. Preserve original deadlines, retry-not-before and queue facts.
   Restart never reconstructs missing raw tokens.
8. Assert second-pass idempotency and distinguish expected summary audits.
9. Scan retained surfaces before teardown using the independent exact-byte oracle.
10. Return defects to their owning implementation/corrective manifest.
    Append new closure evidence in T8 outside Stage 9's historical passage.

Sources:
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2173`,
`docs/development/verification.md:1158`.

**Guard reconciliation.**

- Source/root/pair/profile counts remain 144/34/19/22 -> 144/34/19/22.
- Subprocess importers/token carriers/readers remain 13/4/5 -> 13/4/5.
  Preserve `tests/safety/test_stage6_boundaries.py:106` and its equality at
  `tests/safety/test_stage6_boundaries.py:372`.
- Contract rows/entries/supervision/platform counts remain 52/58/6/26.
  No fake-root, source, schema or migration change.
- Ambient exemption remains 1 -> 1; retain all near misses.
- Stage 10 guard rejects subprocess imports in support/R and incorrect RC/RF placement.
- Preserve the guide's thirteen-importer sentence pinned by
  `tests/safety/test_stage7_boundaries.py:792`.
- A failed platform/recovery assertion requires an owning corrective route;
  it does not authorize production supervision edits here.
- Historical survivor/token/WAL limitations remain recorded until new evidence
  closes precisely the corresponding gap.

**Focused verification.**

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/integration/cli/test_cli_recovery.py tests/integration/cli/test_cli_token_absence.py tests/integration/artifacts/test_finalization_crash_child.py tests/unit/test_cli.py tests/integration/persistence/test_sqlite_restart_reconciliation.py tests/integration/persistence/test_stage9_token_absence.py -q
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/integration/cli tests/integration/process_supervision tests/integration/artifacts tests/integration/persistence tests/safety tests/architecture -q
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-format-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-check-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 mypy-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 schema-generate-check
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 migration-check
```

**Review evidence.** Exact R/RC/RF hosts, handoff/crash/state/purpose coverage,
pre-cleanup survivor sets, actual-holder/descendant handles and ordering,
lost-exit controls, PID-reuse refusal and idempotent replay.
Gated evidence later includes durable retry and conformant token-bearing recovery scans.
Do not claim historical cleanup/WAL susceptibility fixed by new tests alone.
Attach same-subject complete operator verification.

**Section 33 criteria closed.**
33.1/4,6; 33.2/5,9; 33.4/2,4,6-12; 33.5/1,3-6,8-10;
33.6/2-11; 33.7/1,3.

**Decision-register items applied.**
D03,D04,D07,D08,D09,D10,D13,D14.

T7's acceptance subject is exactly the untagged selectors plus the refusal paths.

**Commit message.** `test: prove cli startup and crash recovery over durable state`

### Task 8 - Operator runbook, acceptance ledger and final evidence reconciliation

**Objective.** Document actual operation and all 62 criterion dispositions.
Reconcile exact documentation guards, measured coverage and fresh acceptance
receipts without premature completion claims.

**Prerequisites.** Accepted T1-T7, P1 and immutable evidence references.
The operator completes the separate protected AGENTS documentation companion
before T8's worker base.
B1/B2 and necessary B3 evidence remain visible.
T7's observed commit is the implementation checkpoint;
T8 never guesses or self-references its future documentation commit.

**Interfaces produced.** Local operator runbook; complete 62-cell acceptance
ledger with exact module-qualified selectors; coordinated truthful
README/guide/roadmap status and historical-evidence assertions.

**Files created.**
`docs/development/local-cli.md`
`docs/development/project-1-acceptance.md`

**Files modified.**
`README.md`
`docs/development/verification.md`
`docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md`
`tests/safety/test_stage3_boundaries.py`
`tests/safety/test_stage5_boundaries.py`
`tests/safety/test_stage7_boundaries.py`
`tests/safety/test_stage8_boundaries.py`
`tests/safety/test_stage9_boundaries.py`
`tests/safety/test_stage10_boundaries.py`
`tests/safety/test_gitnexus_development_tooling.py`

**Consumed interfaces.** Accepted Matrices A-C, Matrix D documentation
obligations, section 7.4's map and actual controller/operator receipts.
No new runtime API.

The AGENTS companion is a separate operator documentation change with independent
review, complete verification and human commit.
It changes no execution authority and is excluded from worker bounds.
`PERMITTED_CHANGE_KINDS` is a closed change-kind registry, not a file or permission
to modify protected instructions.

Sources:
`../Crypto_Lab_Dev_Controller/config/controller.policy.json:164`,
`../Crypto_Lab_Dev_Controller/src/clabctl/change_scope.py:20`.

**RED.**

1. `S10::test_stage10_documentation_status_is_exact`: new assertions first reject
   stale active status, invented hashes and unproved completion.
2. `S10::test_stage10_runbook_matches_closed_launcher`: missing runbook fails;
   require exact grammar, path admission, base/correlation and operator-only profile.
3. `S10::test_stage10_acceptance_ledger_has_all_62_cells`: missing ledger fails;
   require every criterion, exact selectors, prerequisites and dispositions.
4. `S10::test_stage10_documentation_preserves_historical_evidence`:
   reject deletion or retrospective promotion of Stage 9 limits/failures.
5. `S10::test_stage10_coverage_evidence_is_measured`:
   reject guessed values, focused-only measurement, altered settings or
   comparisons below either required threshold.
   Explicit pending external receipts remain UNVERIFIED, never passing measurements.
6. `S10::test_stage10_installed_distributions_exclude_real_engines`:
   require bounded installed-metadata checking without engine imports or ambient inspection.
7. Exercise the existing status selectors against proposed prose before reconciling pins:

   ```text
   tests/safety/test_stage3_boundaries.py::test_readme_uses_only_closed_stage3_launcher_setup
   tests/safety/test_stage8_boundaries.py::test_the_roadmap_records_stage_eight_complete_and_stage_nine_complete
   tests/safety/test_stage9_boundaries.py::test_the_guide_records_the_stage_nine_focused_checks_and_evidence
   tests/safety/test_gitnexus_development_tooling.py::test_terminal_outcome_matches_roadmap_status
   ```

   Record the exact intended stale assertion for each genuine RED.
   Unchanged preservation checks are regression evidence, not invented failures.

**GREEN.**

1. Write the runbook with command/input/exit examples, purpose labels,
   initialization/migration/check, ordered startup, cancellation/resume,
   active leases, identity-safe recovery and single-entry purge.
2. Document P1's path admission exactly:
   one absolute local drive-letter path token; no UNC/device prefix,
   wildcard, control/newline or leading `-`; preserve one argument;
   PowerShell checks token shapes, CLI checks semantics.
3. Document offline pinned execution and operator-only `cli-local`.
   T8 owns README text outside Local setup and the verification guide.
   The operator companion owns protected AGENTS prose.
4. Describe a mutually consistent checkpoint of database/revision,
   finalized artifact store, schemas and configuration snapshots.
   Add no backup/restore tool.
5. Populate all 62 ledger cells with exact subject/digest, prerequisite/correction
   commits, module-qualified selectors, admitted commands, results,
   review/verifier IDs, warnings/skips/failures and limitations.
6. Record P0's actual unrounded baseline and actual candidate/merged-main evidence.
   Stable links may point to controller-owned receipts.
   Settle post-freeze receipts externally without editing the reviewed subject.
7. Append T6/T7 closure evidence outside the byte-pinned Stage 9 passage.
   Preserve historical findings and failed runs.
8. Reconcile every assertion below using exact state-specific blocks.
   Do not remove broad guards or authorize arbitrary later-stage claims.

| Guard/source | Required T8 treatment |
|---|---|
| `tests/safety/test_stage3_boundaries.py:1132` | Preserve README Local setup heading, boundaries, preamble, five commands and following prose verbatim |
| `tests/safety/test_stage3_boundaries.py:1934` | Reconcile exact status/header/approved-plan constants and historical hash rules together |
| `tests/safety/test_stage3_boundaries.py:1659` | Preserve `_VERIFICATION_STAGE9_OBLIGATIONS` byte-for-byte; closure evidence sits outside it |
| `tests/safety/test_stage3_boundaries.py:1955` | Preserve the shared obligations assertion; Stage 9 consumes the same constant |
| `tests/safety/test_stage3_boundaries.py:1999` | Add exact new status/closure blocks to subtraction operands; retain residual Stage 10 and `exhaustiv` restrictions |
| `tests/safety/test_stage5_boundaries.py:536` | Reconcile exact approved README block subtraction; preserve stray Stage 10 and all Stage 11 denial |
| `tests/safety/test_stage7_boundaries.py:777` | Replace start denial only with exact evidenced status; preserve Stage 9 history |
| `tests/safety/test_stage7_boundaries.py:792` | Preserve thirteen-importer guide prose |
| `tests/safety/test_stage7_boundaries.py:802` | Preserve whole-document prohibition on unsupported OS-isolation claims and its guarded term |
| `tests/safety/test_stage8_boundaries.py:637` | Reconcile later-stage claim denials through exact truthful permissions; keep unproved completion denied |
| `tests/safety/test_stage8_boundaries.py:1088` | Preserve Stage 8 historical row, retired-row negatives and earlier hashes |
| `tests/safety/test_stage8_boundaries.py:1138` | Replace README not-started sentence with Stage 9's twin reconciliation |
| `tests/safety/test_stage8_boundaries.py:1139` | Replace guide not-started sentence; retain Stage 9 not-started denials |
| `tests/safety/test_stage9_boundaries.py:731` | Replace `_STAGE10_DEFERRED_ROW` membership with approved-plan/evidenced implementation state |
| `tests/safety/test_stage9_boundaries.py:742` | Reconcile one active not-started count and forward clause after evidenced implementation |
| `tests/safety/test_stage9_boundaries.py:746` | Reconcile active header while retaining historical Stages 1-9 facts |
| `tests/safety/test_stage9_boundaries.py:751` | Reconcile README/guide twins with Stage 8's pins and explicit blockers |
| `tests/safety/test_stage9_boundaries.py:763` | Earlier hashes remain once in roadmap and absent from README/guide; new checkpoint is observed |
| `tests/safety/test_stage9_boundaries.py:780` | Preserve six historical focused commands, prose, shared obligations, runtime-rule register and revision names |
| `tests/safety/test_stage9_boundaries.py:790` | Preserve guide closed 48-file wording and deny retired closed 35-file wording |
| `tests/safety/test_stage9_boundaries.py:797` | Preserve README closed 48-schema sentence and thirteen Stage 9 schema paths, subject to D14 |
| `tests/safety/test_gitnexus_development_tooling.py:377` | Advance approved-plan sentence only after acceptance; preserve disabled outcome/manual fallback |

The Stage 8 twin source assertions are :1138/:1139 in this checkout.
The review's :1139-1142 reference identifies the same coordinated obligation.

9. T8 performs the roadmap Planned -> Approved wording and GitNexus approved-plan
   sentence reconciliation after actual plan acceptance.
   The plan-approval commit itself remains plan-only.
10. Preserve the six historical complete focused command lines with target tails:

    ```text
    tests\unit\artifacts tests\unit\audit -q
    tests\unit\persistence tests\unit\domain -q
    tests\integration\artifacts -q
    tests\unit\experiments tests\property -q
    tests\integration\persistence -q
    tests\safety tests\architecture tests\unit\test_schema_registry.py -q
    ```

11. Keep B1/B2/conditional-B3 dispositions explicit.
    Bounded delivery may say implementation delivered/acceptance BLOCKED.
    It may not say Stage 10 or Project 1 complete with required cells open.

Checkpoint authority:
`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md:2194`.

Historical obligation/limit passage:
`docs/development/verification.md:1122`,
`docs/development/verification.md:1158`.

**Guard reconciliation.**

- Source/root/pair/profile counts remain 144/34/19/22 -> unchanged.
  Verifier profiles/steps remain 10/11 -> 10/11.
- Historical focused commands 6 -> 6; Stage 9 listed schema paths 13 -> 13.
  Nominal schemas/actions/hash profiles/tables remain 48/25/20/21 pending D14.
- Approved detailed-plan stage count 9 -> 10 only after actual plan acceptance.
- Active roadmap `Stage 10 not started` count 1 -> 0 after evidenced implementation.
  README/guide active not-started sentences 1 -> 0 each.
- Completion authorization remains 0 -> 0 while any required blocked cell remains.
- Preserve `_VERIFICATION_STAGE9_OBLIGATIONS` and its shared assertions.
  New exact closure block count 0 -> 1; add it to Stage 3 subtraction operands.
- Reconcile Stage 8 :1138/:1139 and Stage 9 :751 together.
  Preserve Stage 9 not-started denials and historical completion facts.
- Preserve exact block containment and planted false-status controls.
  Clock exemption remains 1 -> 1; worker profiles remain 6 -> 6.

**Focused verification.**

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/safety/test_stage10_boundaries.py tests/safety/test_stage3_boundaries.py tests/safety/test_stage5_boundaries.py tests/safety/test_stage7_boundaries.py tests/safety/test_stage8_boundaries.py tests/safety/test_stage9_boundaries.py tests/safety/test_gitnexus_development_tooling.py tests/unit/test_schema_registry.py -q
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 pytest-focused -o addopts= tests/integration/cli tests/safety tests/architecture tests/unit/test_package_layout.py -q
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-format-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 ruff-check-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 mypy-all
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 schema-generate-check
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/invoke-uv.ps1 migration-check
```

**Review evidence.** Every before/after documentation assertion, unchanged setup,
schema/command inventories, AGENTS companion commit, all 62 cells and actual
coverage receipts.
Require independent code/security/diff review and exact branch/merged-main
verification/hygiene evidence.
Section 9 governs publication and the owner-held milestone record.

**Section 33 criteria closed.**
33.1/1-6; 33.2/1-9; 33.3/1-8; 33.4/1-13;
33.5/1-10; 33.6/1-11; 33.7/1-5.

T8 reconciles evidence for these cells.
Documentation alone closes no runtime criterion.

**Decision-register items applied.**
D09,D10,D11,D12,D13,D14.

T8's acceptance subject is exactly the untagged selectors plus the refusal paths.
Recording NOT CLOSED cells can satisfy bounded ledger delivery;
it cannot satisfy full Stage 10/Project 1 acceptance.

**Commit message.** `docs: record local cli operation and project 1 acceptance evidence`

## 9. Verification and acceptance

### 9.1 Serial order and controller execution model

For each task:

1. Establish the accepted parent, exact bounds and prerequisite state.
2. Record focused RED -> minimum GREEN -> focused GREEN.
3. Run broader targets and the five quality profiles serially.
4. Freeze the candidate and complete independent review without concurrent work.
5. Run the complete product verifier alone through controller `SerialVerifier`,
   readiness checks, execution-identity checks and the shared host verifier lock.
6. Require accepted PASSED full verification and journalled independent APPROVE
   covering the same bytes.
7. Have the controller commit exactly the accepted manifest on the accepted parent.
8. Publish the exact implementation-branch commit only through the authorized route.
9. Reconcile interrupted commit/publication operations from durable observations.

A changed subject requires refreshed affected evidence, review and full verification.
A worker assertion establishes none of acceptance, commit or publication.

The commit gate is documented in
`../Crypto_Lab_Dev_Controller/src/clabctl/gitops.py:323`.
The host-lock route is at
`../Crypto_Lab_Dev_Controller/src/clabctl/relay.py:1187`.

The relay's formal independent-review gate currently follows accepted PASSED
verification and reuses a journalled APPROVE only for identical bytes.
The pre-verifier review above is separately scheduled.
If it was not recorded through the admitted review route, the formal review
still runs after verification, alone, before commit.

Source:
`../Crypto_Lab_Dev_Controller/src/clabctl/relay.py:1272`.

Only six profiles are worker-callable:

```text
pytest-focused
ruff-format-all
ruff-check-all
mypy-all
schema-generate-check
migration-check
```

Use only the registered executable form shown in each task.
No chaining, redirection, substitution, alternate executable or caller-selected tool.

Source:
`../Crypto_Lab_Dev_Controller/src/clabctl/launcher_hook.py:42`.

Operator-run operations include `lock-check`, `sync`, `pytest-all`, `build`,
`schema-distribution`, complete verification and P1's `cli-local`.
Every profile outside the six-profile hook remains outside worker permission.
This plan authorizes no acquisition profile or network bootstrap.

The unchanged complete command is:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

Its order remains:

```text
lock-check
-> sync
-> ruff-format-all
-> ruff-check-all
-> mypy-all
-> schema-generate-check
-> migration-check
-> pytest-all
-> build
-> schema-distribution
-> direct git diff --check
```

Sources:
`scripts/verify.ps1:21`,
`scripts/verify.ps1:71`.

Preserve verifier bytes and eleven-step order.
Do not run standalone full-suite verification immediately before that command.
Checkpoint-only evidence does not replace this plan's full per-task gate.

The observed verifier SHA-256 is:

```text
ec818bc7551984878f2f4e57845ec7417b68839d889496acb3e43cb5c895ea7d
```

Its pin is at `tests/safety/test_stage3_boundaries.py:234`.

### 9.2 Host lock, failures, skips, reruns and coverage

Use the shared host verifier lock for heavy verification.
Never overlap a complete verifier with tests, another verifier, edits or review.
Honor readiness deferrals and STOP/PAUSE.

Record every warning, failed command, skipped check and incomplete step.
Later steps omitted by fail-fast execution are NOT RUN.
A partial run is not a pass.

Preserve these three skip-capable source sites:

| Site | Treatment |
|---|---|
| `tests/safety/test_uv_launcher.py:928` | Conditional symbolic-link privilege limitation |
| `tests/unit/experiments/test_experiment_service.py:811` | Same-state cases are covered by separate replay cases |
| `tests/safety/test_uv_launcher.py:1312` | Pydantic importorskip must not actually skip |

These are source sites, not a current skip-instance count.
Where reasons are absent, correlate progress positions with collected parameter
ordering and the inventory where possible.
Label attribution positional and retain its limitation.
Add no skip, xfail, marker, ignored failure or timeout relaxation.

For the carried open-handle-count intermittent:

1. Permit one isolated rerun of the failing command, alone on the host.
2. Preserve both outcomes and all earlier failures.
3. A passing rerun does not establish a fix.
4. A second failure stops acceptance for diagnosis.
5. The exact final subject still requires a PASSED complete verifier.

The inherited rerun/attribution rule is recorded at
`docs/superpowers/plans/2026-08-10-project-1-artifact-finalization-recovery-provenance-audit-implementation-plan.md:2906`.

P0 measures complete-verifier branch coverage on unchanged product code at:

```text
874fb51b4959ca6c3b8e5a2bc640b9af99b176f1
```

Identify any plan-only descendant separately.
It does not change the product-code baseline.

T8 records baseline, final candidate and merged-main evidence under unchanged
measurement settings.
Final coverage must meet both the actual unrounded baseline and configured
90 percent floor.
Do not round down, exclude new modules or substitute an older stage percentage.

Sources: `pyproject.toml:96`, `pyproject.toml:105`.

Focused `-o addopts=` runs supply focused behavior evidence only.
Current coverage, counts, skips and verifier duration remain UNVERIFIED.
Replace planning estimates with actual P0 measurements.
No estimate authorizes overlap or a timeout increase.

### 9.3 Fresh evidence and Task 8 integration

Each evidence item identifies:

- Exact commit or frozen precommit subject digest, parent and manifest.
- Prerequisite/corrective state and admitted command.
- Native outcome and complete transcript.
- Scope, duration, warnings, skips, failures and NOT RUN later steps.
- Review/verifier identities and limitations.
- Exact module-qualified selector for the criterion/facet it supports.

Older stage passes, plan review, focused GREEN, a build or one fake success
do not establish Stage 10 acceptance.

After T8's bounded subject is reviewed, fully verified, committed and published
to its implementation branch:

1. Inspect the complete outgoing task/correction/P1/AGENTS range and pending gates.
2. The operator selects the authorized clean main checkout and verifies ancestry.
3. Integrate with `git merge --ff-only`.
   Divergence refuses integration; preserve both histories without reset/rebase/force.
4. Capture the main subject and run the unchanged complete verifier alone through
   an operator-provisioned admitted main binding and shared host lock.
   Branch verification is not merged-main verification.
5. Perform ownership-aware hygiene:
   no task-owned live/suspended children and no task output roots outside retained
   pytest roots.
   Record unrelated/uncertain processes without adopting or terminating them.
6. Record the exact local-main subject, merged-main result, hygiene outcome and
   any remaining acceptance/publication blockers.

Keep post-freeze receipts in controller-owned evidence.
Do not edit the reviewed tree to insert its future hash or result.

### 9.4 Main-publication boundary

Main publication requires a recorded `MILESTONE_ACCEPTED` for the exact commit,
the target branch checked out and all required gates satisfied.

Sources:
`../Crypto_Lab_Dev_Controller/src/clabctl/gitops.py:233`,
`../Crypto_Lab_Dev_Controller/src/clabctl/gitops.py:565`.

The inspected controller source contains the milestone-note reader but no path
that writes that note.
The owner-held operator must use a reviewed recording procedure.
The concrete admitted main-binding/recording invocation remains UNVERIFIED
until provisioned.

No worker journal edit, invented `publish-main` command or ACCEPT_TASK result
supplies that record.

After milestone acceptance, merged-main verification and hygiene, use only
controller-owned `gitops.publish_branch`.
It validates the authorized destination, scans the outgoing range, refuses
non-fast-forward publication, pushes an exact single-commit refspec without force
and verifies the remote ref.

Source:
`../Crypto_Lab_Dev_Controller/src/clabctl/gitops.py:537`.

If any route or gate is absent, retain the accepted local commit and report:

```text
main integrated locally; merged-main verification <result>;
publication pending <specific reason>
```

Local integration does not establish remote publication or milestone acceptance.
All verification remains offline.
This planning turn performs no network operation.
Any later Git publication uses only the separately authorized controller route;
it authorizes no dependency acquisition, new destination or general network access.

### 9.5 Turn reservation and interruption rules

The observed policy has a 260 total-turn ceiling and disabled per-task turn limit.

Source:
`../Crypto_Lab_Dev_Controller/config/controller.policy.json:78`.

The brief's historical snapshot used 201 turns, leaving 59.
Current usage and remaining capacity are UNVERIFIED.

Planning arithmetic:

```text
8 tasks at 8-15 turns                 = 64-120
planning/closure                     = 10-15
contingency                          = 12-20
further advisor-turn reservation      = 86-155
illustrative ceiling from 201 used    = 356 at the conservative end
```

Corrective missions are excluded from that estimate.
The 155-turn reservation, a corresponding ceiling change or a separately budgeted
successor mission is owner-held.
It is not an assumed extension or current balance.
Record actual authorization and capacity before dispatch.

Honor STOP/PAUSE between operations, including commit and push.
Never clear an unrelated/newer stop or continue past the ceiling.
Preserve candidate bytes, failures, checkpoint and next safe action.
No acquisition, engine installation or Project 2 dependency enters the core.

## 10. Rollback and completion

### 10.1 Per-task rollback

Keep each accepted task's introducing implementation and reconciled guards
in its own commit.
Before reversal, capture current subject, uncommitted diff/new files and evidence.
Preserve uncommitted work in place or an authorized checkpoint.

Use reviewed revert commits for published reversals.
Do not force-reset, clean, discard preserved work or erase refused attempts.
Reverse dependencies in reverse order and rerun affected acceptance gates.

| Task/operator step | Rollback treatment |
|---|---|
| T1 | Remove dependent composition first; revert runtime/ports and guards together; preserve durable data |
| T2 | Revert startup/query/phase changes together; retain pending bytes and refuse unsafe startup |
| T3 | Revert application composition/edge pins; preserve specs, snapshots, queue facts and audit history |
| T4 | Stop dispatch; revert scheduler/bridge/pins together; retain attempts, deadlines and decisions |
| T5 | Stop operational use; revert grammar/composition/projections and census mirrors together |
| P1 | Operator reverts launcher/pins as one reviewed change and re-pins committed hook bytes |
| T6 | Revert tests/support together; retain historical evidence and withdraw affected closure |
| T7 | Revert recovery tests/support together; restore pending-gap disposition without erasing observations |
| T8 | Revert documentation/status/guards coherently; retain external acceptance records |
| AGENTS companion | Operator reverts its documentation commit separately and reconciles profile prose |

No Stage 10 rollback downgrades a database, deletes finalized data or rewrites
schema identities.
Owning-stage corrections retain their own rollback plans.
Every failed/refused review, verification, commit, integration and publication
remains on the record.

### 10.2 Checkpoint, status and completion tokens

Record actual task state, parent/manifest/digest, review/verifier IDs,
commit/publication observations, blockers, carried risks and next action.
Use VERIFIED/ACCEPTED/COMMITTED/PUBLISHED/INTEGRATED only when observed.

Source:
`../Crypto_Lab_Dev_Controller/README.md:328`.

| Checkpoint | Required status |
|---|---|
| Plan drafting/revision | Proposed plan; implementation not begun; no completion token |
| Whole plan accepted | Reviewed plan identity; plan-only commit; no implementation acceptance |
| P0/T1-T7 | Exact accepted prefix/live subject; inherited not-started prose identified as stale |
| P1 closed | Human commit, launcher hashes and hook re-pin; operator-only operational route |
| T8 bounded delivery | Coordinated delivered/acceptance-BLOCKED wording while required cells remain open |
| Local main fast-forward | Local SHA plus merged-main/hygiene result; publication remains separately evidenced |
| Fully accepted milestone | All required cells closed; merged-main pass; clean committed tree; confirmed publication |
| STOP/PAUSE/refusal | Last proved state preserved; no status promotion or completion token |

The implementation completion token is:

```text
STAGE10_COMPLETE_AND_MERGED
```

Emit it only when every condition in section 10.3 is satisfied.
Withhold it while any required B1/B2/conditional-B3 cell remains NOT CLOSED.

The separate planning token is:

```text
STAGE10_PLAN_COMPLETE_AND_MERGED
```

It requires the complete assembled plan's final independent review, advisor
acceptance, required verification and integration on main.
It certifies plan completion with implementation not begun.
This revision chunk emits neither token as a completion claim.

Record only the observed T7 implementation checkpoint as
`STAGE10_IMPLEMENTATION_COMMIT`.
Keep its hash in the roadmap according to the historical rule.
Do not place guessed future hashes in README/guide or self-reference T8's commit.

### 10.3 All 62 criteria and explicit NOT CLOSED cells

The acceptance ledger contains exactly these groups, with no omitted or duplicate
criterion:

| Group | Exact cells | Count |
|---|---|---|
| Foundation | 33.1/1-6 | 6 |
| Canonical data/configuration | 33.2/1-9 | 9 |
| Strategy/capabilities | 33.3/1-8 | 8 |
| Protocol/supervision | 33.4/1-13 | 13 |
| Lifecycle/persistence | 33.5/1-10 | 10 |
| Datasets/artifacts/audit | 33.6/1-11 | 11 |
| Security/exclusions | 33.7/1-5 | 5 |
| Total | Every section 7.4 row | 62 |

Each cell maps to section 7.4's existing E01-E32 evidence and exact Stage 10
closing selectors, prerequisite state and actual final receipts.
An existing selector's presence is not a passing execution result.

Retain these dispositions exactly:

| Dependency | NOT CLOSED cells/facets | Required disposition |
|---|---|---|
| B1 | 33.2/1; normalized-family portion of 33.6/8; 33.6/9 | Owner-approved owning-stage canonical/schema correction; D14 reinspection |
| B2 | 33.6/11; required audit facets of 33.5/1, 33.2/8 and 33.6/7; audit facets of C01, C04 and C07 and every other row tagged B2 in T6's marker column | Owner-approved owning-stage audit/persistence correction, compatibility/migration proof and D14 reinspection |
| Conditional B3 | Correlated creation replay in 33.1/6; complete queue/freeze replay in 33.2/8 and 33.5/2; ordered retry/requeue portions of 33.5/4 and 33.5/8 | Prove original durable QUEUED-CAS fact and stored-spec replay; otherwise owner-held schema/request/spec correction |

For precision, section 7.4's G2-marked required facets remain NOT CLOSED in:

```text
33.1/4-6
33.2/2,4-6,8-9
33.3/1-2,4-6
33.4/1-11
33.5/1-5,7-9
33.6/1-8,10-11
```

These are the specifically described G2 facets, not declarations that every
independently supported facet of those criteria is absent.
They include required startup/maintenance, negotiation, invocation, retry,
cancellation, input/application and audit-derived SYSTEM facts.

The full Matrix C NOT CLOSED workflow set is:

```text
C01-C18 and C20
```

C19, supported read-only projections and independently supported refusal/artifact
facets do not close those full workflows.
No row permits an unsupported mutation with only its audit assertion deferred.

B3 additionally gates the ordered successor/stale-workflow facets identified in
section 7.4, including 33.2/5-6 and 33.5/3,5.
Their required successful workflow evidence remains outstanding.
The conditional corrective trigger and primary B3 cells remain those listed above.

B1 adds no canonical family/converter here.
B2 adds no unrelated action overload or log-as-audit substitution.
B3 adds no silent column, request field, schema, migration or hidden store.

### 10.4 Completion conditions and remaining Project 1 work

Full completion requires all of the following:

1. All 62 cells have fresh final evidence and no required NOT CLOSED facet remains.
2. Matrices A/B and complete C01-C20 pass through their admitted production routes,
   including actual overlap, conformant VALIDATE/RUN scans and pre-cleanup survivor proof.
3. All eleven complete-verifier steps pass offline on the final candidate and
   merged-main subject, with unchanged verifier/coverage settings.
4. Coverage meets both the measured unchanged-base baseline and configured floor.
   Every warning/skip/failure and both outcomes of any permitted rerun are retained.
5. Independent code, security/boundary and diff reviews APPROVE the exact subject.
   P1 and the operator AGENTS companion are complete.
6. No exclusion is breached.
   No new architecture, unplanned canonical/relational schema, real data,
   real engine/backtest, Binance, live/paper trading, wallet, risk, tax, UI, LLM,
   Docker, cloud, server, optimization or promotion feature enters Stage 10.
   No credential/key/withdrawal/leverage/futures/margin/shorting/network/acquisition
   or Project 2 dependency enters the core.
7. The worktree is clean and committed, accepted work is integrated into main,
   merged-main verification and ownership-aware hygiene pass, and the authorized
   controller route confirms the exact remote main commit after milestone acceptance.
8. Checkpoint, ledger, receipts and coordinated status agree.
   No stale evidence, guessed hash, partial verifier or local-only integration
   is promoted into acceptance/publication.

The roadmap's exit remains authoritative:
`docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md:280`.

After bounded CLI delivery, remaining Project 1 items include B1, B2,
necessary B3 proof/correction, any unresolved live RUNNING PID-reuse defect,
and any unclosed required evidence.
Artifact correction operations, diagnostic-reference foreign-key correction
and normalized producers retain their owning/deferred routes from section 1.5.
A documented deferral does not satisfy an acceptance criterion.

Carry the open-handle intermittent, positional skip-attribution limitation,
WAL first-opener susceptibility, historical temporary-root observation limit
and earlier failed runs until evidence resolves their exact scope.

Source: `docs/development/verification.md:1175`.

This continuation performed read-only source/record inspection.
It changed no repository file and ran no project Python, managed-interpreter
discovery, tests, schema generator, build or verifier.
Current runtime results, coverage, installed-state acceptance and publication
remain UNVERIFIED.

## Review disposition register

Each entry identifies the binding review source and original finding location.
Resolution locations refer to this assembled revision's sections and tasks.
These are planning dispositions; execution remains UNVERIFIED.

### Part 2 review

- P2-I01, draft :280-283; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part2-draft1-review.md:12`: resolved in 1.4 P1, 6.7 and T5/T8 by exact path-token admission, explicit first-forwarding design change and documentation ownership.
- P2-I02, draft :616/:689; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part2-draft1-review.md:14`: resolved in 3.1/3.5 and T5/T6 by safe-option regex, preserved harmless echo and distinct nonmatching controls.
- P2-I03, draft :524; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part2-draft1-review.md:16`: resolved in 2.6, 6.2/6.11 and T1 by exact ambient constant/selector and all near misses.
- P2-M01, draft :52-53; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part2-draft1-review.md:18`: resolved in Global Constraints, 7.8 and 9.2 with coverage sources :96/:105.
- P2-M02, draft :369; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part2-draft1-review.md:19`: resolved in 2.2 and T5 with console source pyproject.toml:19.
- P2-M03, draft :68; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part2-draft1-review.md:20`: resolved in Global Constraints and 9.1 with LAUNCHER_PROFILES source :42.
- P2-M04, draft :392; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part2-draft1-review.md:21`: resolved in 2.2 with CORE_PROTOCOL_SUPPORT source :406.
- P2-M05, draft :44; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part2-draft1-review.md:22`: resolved in Global Constraints/1.3 with nondelegable policy source :80.
- P2-M06, draft :120-121; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part2-draft1-review.md:23`: resolved in Global Constraints by lowercase subjects and recorded corrective fix: allowance.
- P2-M07, draft :613; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part2-draft1-review.md:24`: resolved in 3.3 with matching five-column header/delimiter.
- P2-M08, draft :526-527; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part2-draft1-review.md:25`: resolved in 2.6, 6.4/6.5 and T3/T4 by both importer sets and exact reached sets.
- P2-M09, draft :301-303; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part2-draft1-review.md:26`: resolved in P1/6.7 by additive targeted membership and unchanged Python-bearing/verifier pins.
- P2-M10, draft :270-271; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part2-draft1-review.md:27`: resolved in P1, 5.1 and T6-T8 by operator/runbook consumers and hook re-pin before T6.
- P2-M11, draft :201; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part2-draft1-review.md:28`: resolved in 1.2/D08 and T3 by capturing the original QUEUED-CAS instant atomically.
- P2-M12, draft :409-419; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part2-draft1-review.md:29`: resolved in 2.3 and T3/T5 by reserved-key removal and CONFIG.CATALOG_ENTRY_INVALID.
- P2-M13, draft :374-375; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part2-draft1-review.md:30`: resolved in 2.2 and T3 with static callable sources :279/:303.

### Part 3 review

- P3-B01, draft :490/:288-289/:308/:368; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part3-draft1-review.md:10`: resolved in 2.6, 6.3/6.6/6.11 and T2/T4/T5 by exact actual CLI persistence membership and planted experiments/probe.py.
- P3-I01, draft :127/:412/:427-428/:564; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part3-draft1-review.md:12`: resolved in 5.1, 6.8/6.9, 7.1 and T6/T7 by in-process W/X/R, RC/RF children and launch-free support.
- P3-I02, draft :736/:152-171/:26/:223; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part3-draft1-review.md:14`: resolved in 1.2, 4.4, 5.1/5.2 and T3-T7 by B2 refusal before mutation/launch and per-row markers including C01.
- P3-I03, draft :473; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part3-draft1-review.md:16`: resolved in 2.6/6.11 and T1-T5 by advancing quoted census mirrors with inspected literals.
- P3-I04, draft :528-530/:534; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part3-draft1-review.md:18`: resolved in 2.6/6.12 and T8 by coordinated Stage 8 :1138/:1139 and Stage 9 status pins.
- P3-I05, draft :485-486/:332; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part3-draft1-review.md:20`: resolved in 2.6/6.4 and T3 by re-pointing architecture and both Stage 5 planted shapes to process_supervision.
- P3-I06, draft :317; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part3-draft1-review.md:22`: resolved in 1.5/5.3/6.4/6.6 and T3/T5 by reader-contract ownership versus physical confinement ownership.
- P3-I07, draft :39/:94-99; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part3-draft1-review.md:24`: resolved in 4.4 and T2/T5/T8 by invocation_base/schemas selection and separate distribution verification.
- P3-I08, draft :505-511; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part3-draft1-review.md:26`: resolved in 2.6/6.11 and T1/T5 by types confinement and metadata/resources-only importlib use.
- P3-I09, draft :659-724; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part3-draft1-review.md:28`: resolved in 7.3/7.4 and T8 by inlined E01-E32 exact selectors and per-cell evidence keys.
- P3-M01, draft :235; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part3-draft1-review.md:30`: resolved in 6.3/T2 by explicit recovery ownership without a nonexistent END marker.
- P3-M02, draft :798; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part3-draft1-review.md:30`: resolved in 7.8/9.2 with coverage sources :96/:105.
- P3-M03, draft :90; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part3-draft1-review.md:30`: resolved in 4.3 with persistence/disk-failure source specification :2192.
- P3-M04, draft :498; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part3-draft1-review.md:30`: resolved in 6.11/T5 by corrected released/deferred ownership sources.
- P3-M05, draft :533; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part3-draft1-review.md:30`: resolved in 6.12/T8 with Stage 9 header source :746.
- P3-M06, draft :473 definition; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part3-draft1-review.md:30`: resolved in 6.11/T1 with database census definition :1806.
- P3-M07, draft :536; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part3-draft1-review.md:30`: resolved in 6.12/T8 by one shared _VERIFICATION_STAGE9_OBLIGATIONS constant.
- P3-M08, draft :472; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part3-draft1-review.md:30`: resolved in 6.11/T1-T5 by appending outside every database/migration/preflight/restart/store slice.
- P3-M09, C01 marker; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part3-draft1-review.md:30`: resolved in 5.2/T6 by explicit B2 marker and inherited setup gates.

### Part 4 review

- P4-I01, draft :86-112/:240-267/:394-424/:557-595; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part4-draft1-review.md:11`: resolved in 7.3 and T1-T4 by module-qualified RED selectors.
- P4-I02, T1/T2/T4 produced interfaces; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part4-draft1-review.md:13`: resolved in 6.2/6.3/6.5 and T1/T2/T4 with Matrix B interface names verbatim.
- P4-I03, draft criteria lists; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part4-draft1-review.md:15`: resolved in 7.4's reconciled map/inverse and T1-T4 exact criteria sets.
- P4-I04, draft gated selectors; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part4-draft1-review.md:17`: resolved in 7.2 and T3/T4 by explicit tags and bounded untagged/refusal acceptance subjects.
- P4-I05, draft :408-409/:433-435; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part4-draft1-review.md:19`: resolved in 2.3/T3/T5 by by-value catalog construction and exact EngineIdentity validation.
- P4-I06, draft :277-279/:310-311; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part4-draft1-review.md:21`: resolved in 4.3/T2 by unchanged report/count semantics, bounded phase detail and default-shape pins.
- P4-I07, draft :92-93; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part4-draft1-review.md:23`: resolved in 7.2/T1 RED 3 by missing-module RED and planted eager-initialization GREEN proof.
- P4-I08, draft :367-369/:404-405/:419-420; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part4-draft1-review.md:25`: resolved in 1.5/6.4/T3 by naming IB's application reader-contract subject.
- P4-M01, draft :58; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part4-draft1-review.md:27`: resolved in 1.3/T1 by referencing the assembled decision register.
- P4-M02, draft :76-77; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part4-draft1-review.md:27`: resolved in T1 with Clock/IdentitySource/CancellationToken sources :37/:53/:79.
- P4-M03, draft :107-110; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part4-draft1-review.md:27`: resolved in 2.6/6.2/T1 with the exact ambient constant and pair-control selector.
- P4-M04, draft :140-141; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part4-draft1-review.md:27`: resolved in 6.11/T1 by naming all nine census owners and coordinated text mirrors.
- P4-M05, draft :150; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part4-draft1-review.md:27`: resolved in 6.2/T1 by runtime-owned call-time kernel32 binding, types confinement and path-discovery denial.
- P4-M06, draft :458-479; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part4-draft1-review.md:27`: resolved in 6.4/T3 by naming/re-pointing both Stage 5 rows and architecture self-test.
- P4-M07, draft :62-63/:211/:369/:531; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part4-draft1-review.md:27`: resolved in 6.1/8 preamble by explicit no-__init__.py instruction.
- P4-M08, draft :325/:486; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part4-draft1-review.md:27`: resolved in T2/T3 focused commands by unchanged Stage 5/6/7 regression targets.
- P4-M09, draft :628; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part4-draft1-review.md:27`: resolved in T4 with constructor/material-retention/registration sources distinguished.
- P4-M10, draft :20 line length; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part4-draft1-review.md:27`: resolved in section 8 by wrapped prose; exact executable commands remain intact.

### Part 5 review

- P5-I01, draft :80-96; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:14`: resolved in 6.6/6.11/T5 by extending T2's exact persistence set and preserving planted denial.
- P5-I02, draft :181-182/:284-285/:254-263; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:16`: resolved in 5.1/6.8/6.9/7.3 and T6/T7 by exact RC/RF placement and launch-free support.
- P5-I03, draft :114/:226/:329; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:18`: resolved in 7.4 and T5-T7 by criteria sets equal to the authoritative inverse.
- P5-I04, draft :407-411; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:20`: resolved in 6.12/T8 by Stage 8 :1138/:1139 twins and retained Stage 9 not-started denials.
- P5-I05, draft :145-176; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:22`: resolved in 7.2/T6 by marker column, tagged audit/workflow facets and exact bounded acceptance subject.
- P5-I06, draft :32-51/:162-176; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:24`: resolved in 7.2/T5/T6 by module-qualified RED, missing-module negative RED and planted eager/wrong-outcome proof.
- P5-I07, draft :63-65; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:26`: resolved in 2.3/T3/T5 by T3-owned validation/key consumption and T5-owned projection/agreement.
- P5-I08, draft :617; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:28`: resolved in 7.5/10.3 by exact named B2 cells, complete marker set and enumerated G2 facets.
- P5-I09, draft :15-29; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:30`: resolved in 6.6/T5 with produced parser/composition/command/reporting interfaces.
- P5-M01, draft :95-96; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:32`: resolved in T5 by correct released/hash/action/deferred pin attribution.
- P5-M02, draft :409; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:32`: resolved in 6.12/T8 with _STAGE10_DEFERRED_ROW source :731.
- P5-M03, draft :404; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:32`: resolved in 6.12/T8 with Stage 5 containment source :536.
- P5-M04, draft :552; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:32`: resolved in 9.5 with total-turn ceiling source controller.policy.json:78.
- P5-M05, draft :355-356; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:32`: resolved in T8 by identifying PERMITTED_CHANGE_KINDS as a change-kind registry.
- P5-M06, draft :395-396/:402/:413; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:32`: resolved in 6.12/T8 by preserved shared obligations, external closure block and added subtraction operand.
- P5-M07, draft :433; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:32`: resolved in 6.10/6.12/T8 by explicit Planned -> Approved and GitNexus sentence ownership.
- P5-M08, draft :414; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:32`: resolved in 6.12/T8 by distinguishing guide closed-35-file denial from README schema denial.
- P5-M09, draft :183-184; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:32`: resolved in 7.1/T6 by identifying literal child environment as new reviewed behavior.
- P5-M10, draft :170-171/:38-39; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:32`: resolved in 6.8/T5/T6 by distinct unit and integration unknown-argument selectors.
- P5-M11, draft :369-370; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:32`: resolved in T8/9.3 by exact module-qualified selector per cell.
- P5-M12, long lines; `../Crypto_Lab_Dev_Controller/config/records/stage10-plan-part5-draft1-review.md:32`: resolved by wrapped prose; indivisible registered commands and one-line finding records retain exact spelling.

### Planning-brief fact review

- F-B01, brief :260/:191; `../Crypto_Lab_Dev_Controller/config/records/stage10-planning-brief-part1-fact-review.md:12`: resolved in 1.4 P1, 6.7, T5/T6 and 9 by operator launcher/pins commit, hook re-pin and no floor worker bound.
- F-I01, brief :250; `../Crypto_Lab_Dev_Controller/config/records/stage10-planning-brief-part1-fact-review.md:20`: resolved in D06, 2.5/6.5 and T1/T4 by structural scheduler port and CLI concrete bridge.
- F-I02, brief :182/:221-222; `../Crypto_Lab_Dev_Controller/config/records/stage10-planning-brief-part1-fact-review.md:23`: resolved in 2.6/6.11/T1 by clock scanner logic, exact exemption and pair arithmetic.
- F-I03, brief :182/:222 roots; `../Crypto_Lab_Dev_Controller/config/records/stage10-planning-brief-part1-fact-review.md:27`: resolved in 2.6/6.11/T1/T5 by per-module root budgets, sys timing and os/types confinement.
- F-I04, brief :184; `../Crypto_Lab_Dev_Controller/config/records/stage10-planning-brief-part1-fact-review.md:29`: resolved in 6.4/6.5/T3/T4 by exact permitted/actual importer additions and retained persistence denial.
- F-I05, brief :304; `../Crypto_Lab_Dev_Controller/config/records/stage10-planning-brief-part1-fact-review.md:31`: resolved in B3/D08, T3/T4/T7 and 10.3 by durable-fact proof and owner-held corrective branch.
- F-I06, brief :302-305; `../Crypto_Lab_Dev_Controller/config/records/stage10-planning-brief-part1-fact-review.md:36`: resolved in 1.3 by the seven controller classes and explicit owner-held exclusions.
- F-I07, brief :296-329; `../Crypto_Lab_Dev_Controller/config/records/stage10-planning-brief-part1-fact-review.md:39`: resolved in Global Constraints/P0/7.8/T8/9.2 by measured unchanged-base coverage.
- F-I08, brief :195; `../Crypto_Lab_Dev_Controller/config/records/stage10-planning-brief-part1-fact-review.md:41`: resolved in 2.6/6.12/T8 by exact per-file documentation assertions and plan-only approval boundary.
- F-I09, brief :17/G12; `../Crypto_Lab_Dev_Controller/config/records/stage10-planning-brief-part1-fact-review.md:48`: resolved in Global Constraints/T1-T8/9.1 by six worker profiles and separate operator set.
- F-M01, launcher control line; `../Crypto_Lab_Dev_Controller/config/records/stage10-planning-brief-part1-fact-review.md:50`: resolved in Global Constraints/P1 by distinguishing removal loop :653 from fixed control assignment :660.
- F-M02, historical duration; `../Crypto_Lab_Dev_Controller/config/records/stage10-planning-brief-part1-fact-review.md:50`: resolved in 7.8/9.2 by using fresh measured duration and no unsupported historical estimate.
- F-M03, skip sites; `../Crypto_Lab_Dev_Controller/config/records/stage10-planning-brief-part1-fact-review.md:51`: resolved in 7.7/9.2 with :811/:1312 and Pydantic must-not-skip rule.
- F-M04, pending limits; `../Crypto_Lab_Dev_Controller/config/records/stage10-planning-brief-part1-fact-review.md:52`: resolved in 7.6/T6-T8 by preserved historical passage and new closure evidence outside it.
- F-M05, verifier step/whitespace lines; `../Crypto_Lab_Dev_Controller/config/records/stage10-planning-brief-part1-fact-review.md:52`: resolved in 6.13/9.1 with :21/:71 and unchanged eleven-step order.
- F-M06, uv base arguments; `../Crypto_Lab_Dev_Controller/config/records/stage10-planning-brief-part1-fact-review.md:53`: resolved in P1 by correct launcher prefix source :178.
- F-M07, commit casing; `../Crypto_Lab_Dev_Controller/config/records/stage10-planning-brief-part1-fact-review.md:53`: resolved in Global Constraints/T1-T8 by lowercase conventional subjects under 78 characters.
- F-M08, 201-turn snapshot; `../Crypto_Lab_Dev_Controller/config/records/stage10-planning-brief-part1-fact-review.md:54`: resolved in 9.5 as historical snapshot with current balance UNVERIFIED and owner-held reservation.
- F-M09, static methods; `../Crypto_Lab_Dev_Controller/config/records/stage10-planning-brief-part1-fact-review.md:54`: resolved in 2.2/T3 by static StrategyLoader.load and CompatibilityResolver.resolve attribution.
