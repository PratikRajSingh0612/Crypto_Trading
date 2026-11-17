# 4. Architecture and invariants

Controlling source: `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md`, its current accepted amendments, source and tests. This document is a navigational synthesis, not a replacement specification.

## Dependency direction

The canonical domain stays independent of engines, persistence, supervision, networking and the CLI. Application services coordinate domain/ports. CLI composition wires concrete implementations. SQLite owns durable storage through short units of work. Adapter runtimes are separate executables; they do not import into or write the core database. UI and local LLM are later consumers of core services, not alternative systems of record.

## Data and identity

Use canonical Decimal financial values, strict UTC timestamps, prefixed IDs and specified SHA-256 profiles. Reject unknown fields at external/record boundaries. Preserve immutable queue-time strategy, dataset, configuration and policy identities. Replaying an operation must follow its actual identity/idempotency contract, not generate convenient new IDs.

Hashes distinguish content and provenance according to each profile. A checksum is not proof that data was observed correctly, sanitized or produced by an authorized component. Recompute authoritative canonical models and compare them against the actual bytes and intended owner.

## Invocation, supervision and storage

Adapter launch uses explicit registered executables/argument arrays, not arbitrary shell strings. Timeout, cancellation, exit facts, heartbeat and process-tree cleanup have defined precedence. PID reuse matters: a process name or bare PID is not sufficient ownership evidence. Preserve creation identity/handles where the accepted implementation requires them.

Transactions are short and do not span adapter invocation, long hashing or a file move. Compare-and-swap/refusal order is part of the contract. Classified fatal DB failures logically poison a transaction; later calls return its stored failure without SQL, while physical release occurs through the accepted commit/rollback/finally boundary. Storage failures must not be rewritten as absence.

## Artifact finalization

CandidateArtifact and ArtifactRef have different roles, states and paths. RESULT and EVIDENCE identities are distinct. Only eligible successful runs can receive finalized RESULT links and a core RunManifest. Sanitized EVIDENCE may be retained for unsuccessful runs but cannot turn them into success.

The finalization journal bridges file movement and database registration. The RESULT hard deadline is immutable. A shorter renewable lease is capped by it; takeover requires the proper exclusive ownership and atomic checks. Never create success after the deadline or a superseding terminal event. Recovery checks real durable state and actual files.

Canonical core evidence can legitimately contain hashes and IDs. Qualification is based on actual canonical producer/model/source facts, not merely MIME type or a claimed trusted flag. Exact attempt-token detection remains distinct from broad token-shape checks. Uncontrolled strings and free text keep applicable redaction. Never persist transient raw token material in logs, journals, diagnostics or canonical requests.

## Audit and diagnostics

LogRecord is not AuditEvent. Avoid borrowing a semantically unrelated closed audit action to obtain green tests. Structured log projection satisfied the amended Stage 9 test-support requirement only; authoritative application/supervision audit obligations remain a Stage 10/owning-stage schema issue.

Missing input, invalid input, runtime unavailable, storage refusal and unsupported capability are distinct facts. Preserve causal diagnostics without leaking paths, secrets or raw record values contrary to their contracts.

## Dataset path

The accepted offline pipeline has its own package, lock, environment and launcher. It consumes the core package built from an identified checkout. Installed package identity must match the subject tested; a stale wheel can invalidate integration evidence. Interim NDJSON is not Parquet and cannot silently be registered as production-compliant partitions.

## Numerical comparison

Engines can differ in signal timing, fills, fees, slippage, precision and ordering. Verify those dimensions in each adapter. Report unsupported/approximate capabilities honestly. Do not claim seven engines are verified because their names appear in descriptors.

## Product operations versus development tools

The central product uses managed CPython 3.12 and its reviewed execution profiles. A controller or this package's read-only collector running on another Python does not authorize product tests on that interpreter. Keep development tooling and future engine dependencies out of the core environment.

GitNexus remains disabled with evidence. Do not reactivate it just because the new IDE offers a connector. Use source, reference, diff and test analysis.
