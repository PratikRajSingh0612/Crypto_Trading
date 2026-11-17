# 03 - Entire product roadmap and acceptance

## Provenance and status

The thirteen project names/order come from the approved core design's section 32. The detailed acceptance guidance below is a PROPOSED execution brief derived from those boundaries, not a claim that every later specification is already approved or implemented. Read the current repository spec before writing a project's plan; do not silently fill a material product gap with guessed business rules.

Under the user's adopted mandate, a within-boundary specification/plan can be independently reviewed and accepted by delegation. Material unknowns still require a compact human decision. Each gate is real execution evidence. NOT_APPLICABLE, UNAVAILABLE or a placeholder is not proof of an integrated engine.

Project 1's current roadmap and section 33 remain authoritative for its completion. Do not rewrite the core to use a convenient new web stack. Keep economic assumptions explicit across engines; engine disagreement is useful evidence, not votes for a strategy.

## Release checkpoints

- R0: Project 1 accepted, offline fake-adapter core usable from its CLI.
- R1: Projects 2 and 3 accepted: one real-data/real-engine research workflow with finalized results. Deliver this as an intermediate release; keep developing the rest.
- R2: Projects 4-9 accepted: real comparative coverage across the seven adapters for their declared, verified supported scopes.
- R3: Projects 10-12 accepted: hypothetical portfolio/risk, policy-versioned tax analysis and a local beginner-friendly UI.
- R4: Project 13 accepted and whole-product acceptance passes: optional local LLM evidence analysis without weakening deterministic operation.

Do not move the dashboard earlier, drop an engine or reorder dependent projects implicitly. A small early UI can be proposed, but it is a product sequencing decision, not part of this default plan. A platform-incompatible engine is a recorded release blocker or a user-approved scope change, not a fake success.

## P1 remainder - close Stage 8, then Stages 9 and 10

Start with 05_CURRENT_HANDOFF.md and the accepted one-file writer correction. Prove actual process-holder ownership and abrupt exit before reopen. Preserve the failed run and runtime limitation; do not upgrade SQLite or add retry/sleep without a separate decision.

Stage 9: implement only its owned artifact/candidate/reference, RESULT/EVIDENCE, finalized manifest, confinement, checksum, same-volume atomic move, leases, journals/restart recovery, provenance, bounded structured log, diagnostic causal chain and audit work. Plan schema/migration changes in their actual permitted ownership. Test every required crash boundary; partial registration or a file on disk cannot yield success. Preserve recoverable input and source evidence; never finalize raw-token-bearing material.

Stage 10: compose the actual application through the local CLI, strict configuration, startup reconciliation, scheduling, cancellation and every accepted success/non-success path. Produce a specification-to-evidence map for all Project 1 acceptance criteria, operator docs and a real repeatable demo using fake adapters. Complete all established branch/main verification and publication gates. No real engines or data clients enter P1.

## P2 - Local historical data ingestion and normalization

Build the credential-free historical Binance Spot USDT data path after P1. First verify the approved public source, licensing/terms, schema, timestamp units, archive checksums and bounded acquisition policy against current official sources. Do not assume any API endpoint or timestamp representation from memory.

Deliver explicit source adapters, validated normalization, immutable dataset partitions/metadata, lineage and registry integration. Handle duplicates, ordering, invalid prices/volumes, missing bars, symbol/timeframe boundaries, interrupted downloads and idempotent re-import. Never silently fabricate missing prices or join incomplete ranges as complete. Keep raw data and caches outside Git.

Acceptance: deterministic fixture-based ingestion tests offline; a separately authorized bounded real acquisition smoke run; independent normalized row/count/hash checks; re-import without duplication; consumer lookup by immutable dataset identity; licensing and supported-source documentation. Acquisition evidence and offline verification remain distinct.

Do not introduce exchange trading credentials, private endpoints, authenticated testnets or a new direct database writer outside core services.

## P3 - VectorBT Community adapter

This is the first actual engine release, not a replacement of the core. Verify exact version, license, native-Windows feasibility and isolated-runtime requirements before acquisition. Derive the supported subset from the actual pinned framework; unsupported features must be explicit.

Deliver the executable protocol's describe/validate/run mapping, canonical strategy translation, normalized results, native source artifacts, deterministic identities, environment/version records, compatibility outcomes and teardown behavior. Document numeric/precision differences at the engine boundary without converting authoritative core financial fields to binary floats.

Acceptance: run the adapter contract suite; execute a small real engine backtest using a registered dataset; independently check a hand-computable strategy fixture, trade timing, fees, balances and key metrics; finalize the actual native/canonical artifacts; reproduce or explain documented nondeterminism on replay. Test cancellation, malformed input, missing runtime and unsupported capabilities. A mocked engine invocation is not this acceptance.

R1 demo: register dataset -> register supported strategy -> validate compatibility -> run the real engine -> inspect finalized results and provenance -> reopen and reproduce the recorded run. Keep the CLI usable and provide one operator command sequence.

## P4-P9 - Remaining six real adapters

Use a common reusable adapter acceptance contract, not copied engine-specific assumptions.

| Project | Adapter | Additional planning focus, not an assertion of support |
|---|---|---|
| P4 | Freqtrade | Translate its strategy lifecycle and trading assumptions without enabling a live bot or credential path |
| P5 | NautilusTrader | Reconcile event ordering, instrument/precision and execution semantics |
| P6 | Jesse | Verify strategy/runtime constraints and portable signal/order mapping |
| P7 | OctoBot | Identify the minimal credential-free historical execution path and exclude unwanted services/plugins |
| P8 | Hummingbot | Establish whether its pinned version can meet the approved historical/simulated subset without a live exchange path |
| P9 | QuantConnect LEAN | Prove the local runtime/data contract; report the scoped Indian-equities compatibility study separately from any actual implementation |

For EACH project: research official docs and license for a pinned version; assess Windows and runtime feasibility before large coding; write a capability/approximation matrix; build isolated execution; run common contracts; execute a real bounded economic golden case; verify native-to-canonical provenance; and test supervision/error/recovery behavior. Publish a supported/unsupported/unavailable table with evidence.

Do not add Docker, mandatory WSL, hosted execution, authentication, alternate paid editions or a cloud backtest to force an engine to appear integrated. Stop that engine at a precise platform/license gap and request a decision. Continue only genuinely independent authorized work; full seven-engine completion stays false until all required adapters are proven or the user explicitly changes scope.

Cross-engine acceptance compares only declared economically comparable cases. Separate feature/signal agreement from execution/fill/portfolio agreement. Report fees, timing, slippage, precision and data differences; never average returns into artificial consensus or market a majority as proof.

## P10 - Canonical risk controls, hypothetical wallet and paper orchestration

Plan the user-visible paper lifecycle and source of events before implementation. Default to deterministic local historical replay for offline tests; any public streaming input must have its own explicit approved policy. 'Always available' must not silently mean a new background Windows service, cloud backend or credentialed broker.

Implement only simulated balances, positions, orders/fills, fees, reservations and risk checks under explicit versioned rules. Keep paper state distinct from backtest results and real money. Specify restart, idempotency, cancellation, rejection and reconciliation behavior, partial fills and precision before asserting them.

Acceptance: independently calculated accounting examples, conservation/invariant checks, overspend prevention, duplicate-event replay, restart consistency, risk refusals and end-to-end simulated runs. No external real order can be sent; this is proven through the absence/denial of a live-execution path, not merely a UI toggle. No profitability or investment recommendation claim.

## P11 - Indian tax-adjusted performance and TDS analysis

Do not invent current tax law or encode remembered rates as timeless constants. Use current authoritative Indian sources at planning time. Record legal/source citations, financial year, applicable events, currency conversion policy, effective dates, assumptions and unsupported cases in a versioned policy specification.

Distinguish hypothetical research estimates from actual filing liability. Model cashflow withholding separately from economic performance and final tax estimates according to verified policy. Do not assume TDS and tax are interchangeable or that backtest events imply real taxable transactions.

Acceptance: sourced rule-to-test map; independently computed examples and rounding/date boundaries; version selection; immutable input links; clear gross/net/withholding views; fail-closed or explicitly unsupported treatment where rules are unresolved. No filing, payment, exchange credentials or collection of private tax documents. Material unresolved legal interpretation is a human gate, not an LLM guess.

## P12 - Local dashboard and beginner-friendly workflow

Design over real application services and finalized records. No second business-logic implementation or direct ad-hoc UI writes to the core database. Select a local Windows-compatible delivery architecture; do not choose Next.js/Vercel merely because those skills exist. A loopback browser bridge, if proposed, needs an explicit reviewed local-only boundary decision; never conflate it with permission for hosted/public service deployment.

Required user journeys: setup/health, dataset and strategy selection, compatibility explanations, start/cancel/progress, comparison with exclusions/approximations, evidence and provenance drilldown, paper-account visibility, tax-policy context and intelligible failures. Provide empty/loading/stale/error states, keyboard access and readable formatting. Values, units and currency must be explicit.

Use the user's preferred analytical visual direction as a preference, not an inaccessible image. Show a mockup or actual render for each substantive iteration. Use available local browser tools with a dedicated test profile; do not inspect personal cookies or accounts.

Acceptance: end-to-end journeys against actual services, not dummy button handlers; accessible navigation; screenshots reviewed for clipping/density/state clarity; data matches independent core reads; no false running/success state; safe import/export and cancellation; no unexpected listener or remote request. Document installation and local operation.

## P13 - Local LLM analysis of immutable evidence

The LLM is a read-only explanatory aid, never an authority over canonical values, trade execution, risk, taxes or strategy approval. Deterministic operation must work with the model absent.

Choose a genuinely local compatible model/runtime, license and resource budget using current evidence; exact model weights require separately approved acquisition. No cloud Claude/API, hosted Vercel AI service or implicit fallback. Do not claim offline privacy without testing network absence for the actual path.

Feed only permitted immutable evidence with stable references, bounded context and explicit missingness. Treat strategy names, logs and reports as untrusted text; embedded instructions cannot request shell tools, file writes, data export or credential access.

Acceptance: every numeric assertion is grounded to deterministic evidence or labeled unavailable; citations resolve; unsupported questions produce uncertainty rather than fabrication; injection cases cannot gain authority; the model cannot alter runs or wallet state; local resource/cancellation limits; whole-app regression with the model disabled. Generated prose is separate from authoritative records.

## Whole-product completion

FULL_PRODUCT_COMPLETE requires actual accepted evidence for every required project, not merely scaffolds, mocks, green core tests or a documented unsupported adapter.

Provide a versioned feature/capability matrix, reproducible local install instructions, environment pins/licenses, normal and adverse end-to-end workflows, clean builds, source-linked verification, safe demo data, known limits and accepted local/remote commit identities. Verify offline core behavior independently of the optional download paths. Keep data, models, engine environments and runtime artifacts out of source publication unless explicitly licensed and approved.

If a mandatory engine or feature is blocked, issue an accurate partial-release report with the missing obligations. Do not use the full completion marker. No deadline or percentage is fabricated from the number of project headings.
