# P10 - Risk controls and hypothetical wallet

## Evidence status
Unplanned implementation. Read `docs/03_CURRENT_STATE.md` and actual local evidence before dispatch.

## Target outcome
Conservation, idempotency, risk refusals and restart-safe simulated accounting.

## Dependencies
Stable order/fill/fee/result semantics and core services. Shared contracts belong to their owning workstream. Do not invent a parallel model.

## Planning status
The following execution brief is proposed guidance derived from the approved project boundary; it is not a fabricated accepted task list. Existing accepted plans take precedence for exact behavior and must be reconciled with current owner amendments.

## Proposed slices
Specify simulated orders/fills/fees, balances and reservations from stable canonical records. Define risk policies, idempotency, partial fills, cancellation and restart. Implement conservation/overspend and replay tests with independently calculated cases. Add paper orchestration only after its event source and semantics are explicit.

## Acceptance
No real-order path exists; simulated ledgers remain distinct from backtests; repeated events cannot double-debit; restart recovers exact state; limits/refusals are traceable and deterministic. Do not reinterpret always-available as an unapproved background service.

## Antigravity execution instruction
Use the master mission and current source, one writer per path and one heavy verifier. Produce a compact just-in-time plan only where none is accepted. Reuse relevant evidence, perform focused test-first implementation and independent review, then the required final acceptance on the exact subject. Commit/push accepted work and select the next eligible task without another routine owner prompt. Save a precise checkpoint before session limits.
