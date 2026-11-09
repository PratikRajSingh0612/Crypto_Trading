# Stage 9 canonical evidence validation clarification

- Date: 2026-11-09
- Status: accepted (prospective ruling of the product owner, applied in Stage 9
  Task 7; the pinned plan is not edited)
- Scope: Project 1, Stage 9 plan
  `docs/superpowers/plans/2026-08-10-project-1-artifact-finalization-recovery-provenance-audit-implementation-plan.md`

## Context

Two accepted plan clauses collide in Task 7.

1. Plan 6.4 and Task 4 (`artifacts/validation.py`, the `REDACTION` stage,
   pinned by `test_result_scans_the_exact_token_and_evidence_scans_token_shape`)
   refuse any text `EVIDENCE` candidate carrying a run of 32 or more url-safe
   characters as `SECURITY.SENSITIVE_MATERIAL_LEAKAGE`, so that a digest-looking
   placeholder is never mistaken for the absence of the raw attempt token. The
   rule is the audit redaction's token shape restated as bytes (plan 2.6).
2. Plan 4.6 has the core produce evidence as canonical JSON and JSON Lines:
   the sanitized adapter result manifest, the sanitized validation result, the
   protocol capture regenerated from the ledger, the adapter descriptor parse
   and the diagnostic report. Every such record carries SHA-256 digests and
   prefixed uuid4 identifiers, and the field name
   `sanitized_adapter_result_manifest_hash` is itself a 38-character url-safe
   run. Under clause 1 every one of those registrations fails; Task 7 cannot
   finalize the evidence the plan requires after every outcome (RC-9) or for a
   describe conclusion.

The first Task 7 attempt reported the collision and stopped. The owner's ruling
of 2026-11-09 resolves it prospectively; this record states the ruling as
implemented so a reader of the pinned plan can reconcile the two clauses.

## Decision

Canonical qualification is provenance-scoped and runs through the existing
producer/registrar boundary; no general trust framework is introduced.

- `artifacts/ports.py` adds `CanonicalEvidenceQualifier` and
  `CanonicalQualification`. The production `PurposeRegistrar` of the
  `experiments` composition (`ResultRegistrar`, delegating to
  `EvidenceRegistrar`) satisfies the qualifier protocol beside the registrar
  protocol. The finalizer consults the qualifier only when its registrar
  answers it; the reconciler, which builds its finalizer from the registrar it
  is handed, therefore qualifies the same way without a change to
  `artifacts/recovery.py`. The Task 6 memory registrar answers no contract, so
  the Task 6 suites keep today's whole-content behaviour.
- Qualification requires every part to agree: the candidate is a `CORE`
  `EVIDENCE` candidate of a canonical medium at or below the parse ceiling;
  its role, owner kind, correlation kind and fixed staging leaf are the
  producer's; every record parses from its bytes as exactly the producer's
  model and re-serializes to those very bytes (canonical-byte enforcement);
  and the records agree with the authoritative facts: the stored text of the
  `sanitized_adapter_result_manifests` or `adapter_validation_results` row,
  the ledger's events in sequence order, the recorded diagnostics, the
  `DESCRIBE` invocation of an adapter owner, the invocation of a run owner.
  The structured stderr fallback record (`retained_byte_count`, `truncated`,
  `source_hash`, nothing else) qualifies against the invocation. A media type,
  a kind label, the `CORE` flag or a valid parse alone never qualifies.
- Content that is not the kind's model answers no contract and keeps the
  whole-content token-shape protection (a forged label, a non-canonical
  serialization, stderr free text that happens to be JSON). Content that is
  the model but disagrees with the facts is `ARTIFACT.VALIDATION_FAILED` at
  `SCHEMA` and quarantined. Facts that could not be read keep the storage
  posture (`ARTIFACT.MOVE_FAILED`, the candidate stays `VALIDATING`).
- A qualified candidate skips the whole-content scan; its uncontrolled strings
  are held to the same token-shape rule field by field. A string is controlled
  only when its declared type is a closed identifier or digest grammar of
  `domain/identifiers.py` or a literal; free text, adapter-chosen identifiers,
  error codes, versions and dynamic mapping keys are uncontrolled. The describe
  header's echo of the envelope's `executable_hash`, which the parse validator
  proves equal, is the one mirrored value. The global redaction patterns are
  unchanged.
- JSON Lines content is validated record by record: a final newline, no empty
  record, every line one strict document, before the qualifier is asked.
- Independently of qualification, available `AttemptTokenMaterial` is passed
  through the existing scanner for either purpose, binary evidence included:
  the caller's transient material (`finalize(..., token_material=...)`, the
  conclusion's frame before the terminal close removes `request.json`) or the
  `token_material` lookup. Before use it is validated against the authoritative
  run and invocation: it names the owner's run and hashes to the run's stored
  `attempt_token_hash`; for evidence the invocation it was answered for must
  belong to that run too, while a `RESULT` request's run-command invocation is
  verified by the T1 lease check itself; a mismatch is the invariant and
  nothing is written. `scan.token_found` is refused
  regardless of qualification; a document already decoded is also inspected
  string by string so alternate JSON escaping hides nothing. Material lives in
  the call frame only and never reaches a canonical request, row, journal,
  diagnostic, audit detail or log. The `ARTIFACT_VALIDATED` audit fact records
  `exact_scan` and `canonical` as booleans, so a token-free validation is never
  represented as a successful exact scan.
- Token-free operations stay supported: a describe conclusion, a `SYSTEM` or
  snapshot owner, and evidence finalized after the raw bytes were closed
  validate without material. Recovery without raw material qualifies canonical
  evidence only through the reconstruction above; raw material is never
  recovered or retained to enable optional evidence, and the run's semantic
  outcome never changes because optional evidence could not finalize.

## Consequences

- The Task 4 pin `test_result_scans_the_exact_token_and_evidence_scans_token_shape`
  keeps its assertions: unqualified text evidence with a digest is still
  refused. The Task 4 contract test now admits the owner run's material for an
  `EVIDENCE` candidate and refuses another run's before any open.
- The three input snapshot kinds (`AUDIT` correlation, caller-supplied bytes
  proved equal to a registry fact) answer no contract in Task 7 and keep the
  whole-content protection; Task 8, which exercises them, decides their
  qualification.
- `test_lease_refused_when_the_row_reads_of_the_check_fail` counts the row
  reads of the T1 lease check from the start of `finalize`; the phase-1
  association read of the run row moves the check's run read from the second
  to the third `engine_runs.get`, while its invocation read stays the first
  `command_invocations.get` (a `RESULT` reads no invocation in phase 1).
- The plan's Task 3-excluded census arithmetic is unchanged by this ruling.
