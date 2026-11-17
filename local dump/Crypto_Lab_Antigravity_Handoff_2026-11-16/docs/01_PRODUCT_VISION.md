# 1. Product vision and the complete user journey

## Destination

Continue Crypto Trading Lab as a personal, Windows-local, engine-neutral research and simulated-trading application. Its purpose is to let the owner describe a strategy, validate the data and assumptions, run supported simulations through different engines, inspect trustworthy results, and understand differences rather than hide them.

The destination is not merely a library, a mock demonstration, a prompt collection or an autonomous coding controller. The autonomous coding controller was development infrastructure. The product is the research application the user ultimately operates.

## Original scope retained from the approved architecture

- Initial economics: Binance Spot instruments quoted in USDT; long-only; no leverage, shorting, futures or margin.
- Historical data and simulated trades; no real orders, custody, withdrawals or exchange trading credentials.
- Seven separately verified engines: VectorBT Community, Freqtrade, NautilusTrader, Jesse, OctoBot, Hummingbot and QuantConnect LEAN.
- Canonical risk controls and an always-available hypothetical wallet/paper-trading workflow.
- Versioned Indian tax-adjusted performance and TDS analysis; no invented legal assumptions.
- A local beginner-friendly dashboard over deterministic services.
- Optional genuinely local LLM explanation of immutable evidence, not authority over execution or numeric truth.

The newer owner direction removes old development-provider dependencies and routine process approvals. It does not explicitly convert the research application into a live-money trading bot or authorize public deployment.

## Target workflow: first useful research release

1. Import a supported local historical file or acquire an explicitly selected public-data sample through the permitted data workflow.
2. Validate timestamp units, UTC, numeric representation, ordering, duplicates, missing intervals and checksums. Surface quality warnings rather than silently invent bars.
3. Register immutable dataset metadata and a production-compliant partition representation through core-owned services.
4. Select or author a supported declarative strategy and explicit assumptions for fees, slippage, sizing, timing and warm-up.
5. Ask the capability resolver which engine/adapter can execute it exactly, approximately with disclosed differences, or not at all.
6. Create and queue the experiment with frozen strategy/data/configuration identities.
7. Launch the isolated adapter through the core supervisor. Display actual lifecycle state; allow safe cancellation.
8. Validate candidate outputs, record the source/native artifacts, finalize eligible RESULT files, and create the core RunManifest only after successful registration.
9. Inspect trades, diagnostics, provenance and reproducibility information. A failed run may retain sanitized EVIDENCE but never masquerade as a successful research result.
10. Close and reopen the application and reproduce the recorded result or explain versioned, documented nondeterminism.

## Later end-user workflows

### Comparative research

Run the same eligible strategy/data pair through several adapters. Separate feature/signal agreement from fills, fees, execution ordering and portfolio results. Explain declared approximations and unsupported features. Do not use majority voting or average returns as a fabricated consensus.

### Hypothetical wallet and paper trading

Operate explicit simulated balances, reservations, orders, positions, fills and risk limits. Idempotently handle repeated events, restart and cancellation. No code path submits an actual exchange order. The source of paper events and any streaming data must be specified, not assumed.

### Tax-adjusted analysis

Choose a cited, effective-dated policy and display assumptions and limitations. Separate withholding/cashflow treatment from estimated ultimate tax treatment. Research results are hypothetical; do not present them as filing advice or real taxable transactions without their actual facts.

### Dashboard

Browse datasets and quality; author/import strategies; inspect compatibility; start eligible experiments; view running/cancelled/failed states; inspect results and artifacts; compare engines; inspect paper balances and tax estimates when implemented. The UI is a consumer of core services, not a second direct database writer.

### Local LLM

Ask explanations grounded in saved evidence. Every quantitative assertion must resolve to deterministic records or be labelled unavailable. Untrusted text in logs or strategy names cannot grant tool access. With the model unavailable, deterministic workflows continue to function.

## Intermediate release gates

R0: complete Project 1 with fake adapters and its full acceptance matrix.
R1: core + real data path + one real engine + saved reproducible results.
R2: all seven required adapters, each with evidence-backed supported scope.
R3: risk/paper wallet + sourced tax analysis + local UI.
R4: optional local evidence assistant and full-programme acceptance.

These checkpoints are planning aids inherited from the historical handoff, not proof that any later release has been delivered. A useful R1 release does not delete the remaining engine backlog.
