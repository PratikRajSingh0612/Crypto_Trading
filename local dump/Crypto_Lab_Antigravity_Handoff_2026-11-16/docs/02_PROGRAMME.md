# 2. Programme scope: projects, stages and tasks

There are thirteen PROJECTS. Project 1 contains ten STAGES. Stages and slices contain TASKS. Do not equate these counts with equal effort or overall percentage completion.

The detailed later-project slices below are proposed work decomposition. Only exact tasks read from an accepted repository plan and associated evidence can be labelled accepted.

| ID | Project | Evidence status | Dependencies | Definition of delivered outcome |
|---|---|---|---|---|
| P1 | Engine-neutral core | Stages 1-9 published; Stage 10 Task 1 published; completion still pending | P1-S10 plus owning-stage B1/B2/B3 corrections | Core-only offline CLI acceptance with fake adapters |
| P2 | Historical data ingestion and normalization | Accepted slices and contract tests published on development branches; combined local merge reported, publication unconfirmed | Core dataset contracts; production output and finalization integration | Registered reproducible datasets with explicit quality and provenance |
| P3 | VectorBT Community adapter | Pinned 1.2.0 environment/bootstrap commit published; adapter acceptance unconfirmed | Pinned executable protocol and approved isolated environment; dataset semantics | One actual supported backtest with checked trades and finalized results |
| P4 | Freqtrade adapter | No accepted implementation established | Common adapter acceptance and version-specific local feasibility | Real credential-free historical execution within declared capabilities |
| P5 | NautilusTrader adapter | No accepted implementation established | Same shared contracts; event-order and precision mapping | Checked event-driven backtest and canonical provenance |
| P6 | Jesse adapter | No accepted implementation established | Version/runtime/strategy compatibility | Actual supported simulation, not a fake adapter |
| P7 | OctoBot adapter | No accepted implementation established | Minimal local historical path and plugin/service exclusions | Actual historical execution without live-account dependency |
| P8 | Hummingbot adapter | No accepted implementation established | Prove historical/simulated feasibility without live exchange | Evidence-backed integration or a precisely reported unresolved capability gap |
| P9 | QuantConnect LEAN adapter | No accepted implementation established | Local runtime/data/license/platform feasibility | Verified local adapter plus separate Indian-equities compatibility study |
| P10 | Risk controls and hypothetical wallet | Unplanned implementation | Stable order/fill/fee/result semantics and core services | Conservation, idempotency, risk refusals and restart-safe simulated accounting |
| P11 | Indian tax-adjusted performance and TDS | Unplanned implementation | Finalized records; sourced effective-dated policy | Traceable calculations with independently checked examples |
| P12 | Local dashboard | Unplanned implementation | Stable application/service interfaces for delivered features | Usable accessible local workflows backed by real application state |
| P13 | Local LLM evidence analysis | Unplanned implementation | Reliable immutable evidence and deterministic workflows | Local optional grounded explanations without write/execution authority |

## Dependency policy

Finish the core critical path while one genuinely independent product task uses the spare worker slot. All engines consume agreed core contracts but need not be arbitrarily implemented in strict numerical order once the first adapter establishes the real integration pattern. Wallet/tax/UI/LLM implementation may start only when the consumed contracts are ready; a mock UI or invented tax model is not completion.

No later-project dependency may leak into Project 1 merely because its worktree shares the same repository. Coordinate shared schemas/migrations through one owner and consumer tests. Integrate small accepted slices, not thirteen separate products at the end.

## First candidate priorities after takeover

1. Preserve and reconcile any active verification, local integration merge and uncommitted work.
2. Continue the real next Stage 10 task, reported as S10-T2, after inspecting its accepted prerequisites.
3. Resolve B1/B2/B3 through owning-stage corrective work; they prevent complete Project 1 acceptance even if bounded Stage 10 tasks pass.
4. Reuse the accepted P2 work and current integration evidence; do not recreate its environment or reader.
5. Reuse the new P3 bootstrap and select the first real engine task from its actual accepted plan.
6. Fill only an unused second writer slot, with one heavy test owner across the host.
