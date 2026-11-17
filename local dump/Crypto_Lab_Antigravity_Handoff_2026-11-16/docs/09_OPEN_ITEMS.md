# 9. Open items that matter to completion

## Stage 10 owning-stage blockers (source inspected)

Source: `docs/superpowers/plans/2026-08-10-project-1-cli-composition-end-to-end-acceptance-implementation-plan.md` at `ba4412a...`, sections 1.2 and the 62-cell acceptance matrix.

### B1: normalized canonical record family

CanonicalOrder, CanonicalFill, PositionSnapshot, PortfolioSnapshot and EquityPoint/supporting contracts remain deferred because Stage 9's conditional normalized-family task did not execute. Missing schemas/consumer guarantees must be addressed through an owning-stage corrective plan. A normalized-role JSON fixture or existing provenance type is only partial evidence. Stage 10 bounded tasks cannot close those criteria by renaming fixtures.

### B2: application audit vocabulary

The closed AuditAction vocabulary cannot faithfully represent every required application fact: registration, experiment lifecycle, compatibility decisions, attempts/retries, invocation facts, descriptor negotiation, protocol acceptance/rejection, migration/reconciliation and policy/configuration facts. These are required fact classes, not invented enum member names.

A suitable correction needs published-schema compatibility, relational action-constraint/migration evidence and consumer reinspection. No borrowing unrelated actions and no replacing authoritative audit with logs. The published plan refuses an unsupported required mutation before mutation or child launch. A read-only/refusal-path task may pass while whole-product acceptance remains blocked.

### B3: durable ordering and creation idempotency

ExperimentRow has mutable created/updated times but no dedicated queue instant; ExperimentCreationRequest lacks a correlation field in the inspected base. Inspect the plan's conditional branch before changing schemas. Existing durable facts can sometimes satisfy the requirement; mutable updated_at must not be mistaken for immutable queue order. Do not invent idempotency by drawing new identities.

## Runtime/test observations

- Historical Hypothesis slow-generation/deadline behavior, handle-count settling and natural-exit/PID-line timeouts remain observations unless the exact defect is independently closed.
- The interrupted-writer ownership correction does not remove the narrower SQLite mapped-SHM first-opener/recovery limitation.
- The two-file Stage 10 baseline correction passed and was published; preserve the three unresolved timing observations rather than reopening all accepted baseline work.
- Previous inability to enumerate Windows Temp is UNKNOWN hygiene, not proof that it is empty.
- Old monitor pipelines could leave children after their session ended. Investigate actual owned processes; do not kill by process name.

## Data/engine gaps

P2 interim NDJSON is not production Parquet. Temporary-database golden registration is not persistent registration/finalization of a real dataset. The bounded two-date real-source test was proposed/authorized in chat; its successful execution was not supplied here. Verify local evidence before asserting no run or inventing success.

P3 environment bootstrap is now published. No accepted engine backtest is established by that commit alone. Inspect its actual task plan and local evidence.

## Migration gaps

Current local main, merge 6678c15's full identity/outcome, active S10-T2 work, exact controller archive roots and Antigravity tool permissions must be checked locally. Full task plans are located in the repository; do not treat inaccessible originals as nonexistent.

## Administrative issues already delegated

Ordinary commit grouping, same-scope file-map repair, complete acceptance manifests and expected-branch publication reconciliation do not need another human-only ruling. The exact supported implementation must still preserve data and verification integrity. A model may not label a changed financial/security requirement merely procedural.
