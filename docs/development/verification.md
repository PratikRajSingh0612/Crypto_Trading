# Development Verification

Project 1 verification is local, Windows-oriented, and independent of trading
engines, Binance, databases, Docker, WSL, credentials, ambient environment
configuration, and application networking.

## Prerequisites

Run these read-only checks from the repository root:

```powershell
uv --version
uv python find --managed-python --system --no-python-downloads 3.12
```

The second command must resolve the already installed user-local uv-managed
CPython 3.12 and must not download an interpreter. `--system` skips the project
`.venv` during discovery, `--managed-python` still requires a uv-managed
install, and `--no-python-downloads` prevents acquisition. Normal execution
goes through the repository `scripts/invoke-uv.ps1` child launcher; every
profile except the five bootstrap profiles runs against the project `.venv`.
Stop without installing anything when either prerequisite is absent.

`.python-version` requesting `3.12`, `python-preference = "only-managed"`, and
`python-downloads = "manual"` remain ordinary project metadata for uv commands
issued outside the closed launcher. They are not the enforcement mechanism for
launcher profiles: the launcher passes `--no-config` on every profile, so uv
consults neither `.python-version` nor `[tool.uv]`. The launcher's own fixed
`--managed-python` and `--no-python-downloads` arguments carry that policy
instead.

## Fresh-worktree bootstrap

A new worktree carries tracked metadata but no `.venv`. After `uv.lock`
exists, `sync` is the supported first launcher operation there: it creates and
populates `.venv` from local locked content only, and must precede every
Python-bearing profile.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 sync
```

Five bootstrap profiles (`lock-resolve-offline`, `lock-check`, `sync`,
`lock-acquire`, and `sync-acquire`) dispatch before the launcher resolves
`.venv\Scripts\python.exe`. They therefore require no existing project
environment and pass no `--python` argument at all. They still validate that
the project `pyproject.toml` is a regular file below the repository root, and
that the root and any existing `.venv` prefix traverse no reparse point.

Their interpreter is constrained by the launcher's fixed `--managed-python`
and `--no-python-downloads` arguments together with the project
`requires-python = ">=3.12,<3.13"`: uv selects a user-local uv-managed CPython
satisfying that range and never falls back to an unreviewed system
interpreter. `--managed-python` alone names no exact patch release. Because
the launcher also passes `--no-config`, these profiles consult neither
`.python-version` nor `[tool.uv]`.

Once `sync` has created and populated `.venv`, every Python-bearing profile
resolves and validates `.venv\Scripts\python.exe`, proves it remains inside
the project environment, and runs its fixed Python or tool command against
that interpreter. The launcher sets the fixed Pydantic plugin-discovery
control in the child environment on every profile, bootstrap included.

`lock-resolve-offline`, `lock-check`, and `sync` are explicitly offline;
`lock-acquire` and `sync-acquire` are the two profiles that omit `--offline`,
and both remain separately approval-gated. If cached packages are
insufficient, stop. Show and obtain one-time approval for the exact Task 1
`sync-acquire` launcher profile, then return to the launcher `sync` operation,
which expands only to the fixed offline form. Acquisition is not verification
and never permits a non-offline ordinary command.

## Complete verification

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

The script stops at the first failure and runs, in order:

1. launcher `lock-check`
2. launcher `sync`
3. launcher `ruff-format-all`
4. launcher `ruff-check-all`
5. launcher `mypy-all`
6. launcher `schema-generate-check`
7. launcher `pytest-all`
8. launcher `build`
9. launcher `schema-distribution`
10. direct `git diff --check`

A successful partial command does not establish repository acceptance. Schema
generation checks the closed 35-file registry without writing; distribution
verification byte-compares the reviewed source schemas with their sole wheel
and sdist locations.

## Focused checks

Use focused checks during red-green development, then run complete verification:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\domain -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\configuration -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\datasets -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\adapters tests\unit\artifacts -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\property -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\safety -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 ruff-check-all
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 mypy-all
```

Stage 4's focused targets are the following. `tests\unit\strategy`,
`tests\unit\capabilities`, and the `tests\architecture` package-boundary module
are new in Stage 4; `tests\unit\test_schema_registry.py` and
`tests\integration` are older modules whose contract Stage 4 widened from eleven
schemas to twenty.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\strategy -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\capabilities -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\test_schema_registry.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\architecture -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\integration -q
```

Stage 5's focused targets are the following. `tests\unit\experiments`,
`tests\integration\experiments`, `tests\safety\test_stage5_boundaries.py` and the
Stage 5 modules under `tests\unit\domain` and `tests\property` are new in Stage 5;
`tests\unit\test_schema_registry.py`, `tests\integration`, `tests\architecture`
and `tests\safety` are older modules whose contract Stage 5 widened from twenty
schemas to 27 and extended with the `experiments`
and `adapters` package boundaries.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\experiments -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\domain tests\unit\configuration -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\property tests\architecture tests\safety tests\integration -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\safety\test_stage5_boundaries.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\test_schema_registry.py -q
```

Stage 6's focused targets are the following. `tests\unit\adapters`,
`tests\contract` (the offline harness and the 52-row contract matrix over the
executable fake adapters under `tests\fake_adapters`),
`tests\integration\adapters` and `tests\safety\test_stage6_boundaries.py` are
new in Stage 6; `tests\unit\test_schema_registry.py`, `tests\integration`,
`tests\architecture` and `tests\safety` are older modules whose contract Stage 6
widened from 27 schemas to the final registry count of 35 and extended with the
Stage 6 boundary guard.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\adapters -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\contract -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\safety\test_stage6_boundaries.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\integration -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\test_schema_registry.py -q
```

Stage 7's focused targets are the following. `tests\unit\process_supervision`,
`tests\integration\process_supervision` (the supervised 52-row contract matrix
and the Windows platform cases over the production supervisor),
`tests\unit\experiments\test_supervision_lifecycle.py`, the two Stage 7 property
modules and `tests\safety\test_stage7_boundaries.py` are new in Stage 7;
`tests\unit\domain`, `tests\unit\experiments`, `tests\property`,
`tests\contract`, `tests\safety`, `tests\architecture` and `tests\integration`
are older modules whose contract Stage 7 extended with the monotonic clock, the
cancellation token, the harness seam and the Stage 7 boundary guard; the
registry stays at 35 schemas.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\domain tests\unit\process_supervision -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\experiments tests\property -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\integration\process_supervision -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\contract tests\safety tests\architecture tests\integration -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\safety\test_stage7_boundaries.py tests\unit\test_schema_registry.py -q
```

The `addopts` override removes the repository-wide coverage threshold only
from a focused diagnostic run. The later complete suite must satisfy the
configured branch-coverage gate.

Ordinary verification is offline throughout. No focused or complete check
contacts the network, and no acquisition profile is ever cited as verification
evidence.

## Schema workflow

Schemas are generated only from the explicit registry:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 schema-generate-write
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 schema-generate-check
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 build
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 schema-distribution
```

`--write` is an intentional source update reviewed in the schema task. The
operator must supply the reviewed repository `schemas` root explicitly; the
generator targets only the 35 fixed lexical descendants, rejects an existing
symlink root or entry, and refuses every unexpected file without deleting it.
Stage 7 retains physical ancestor reparse-point and volume containment. The
`--check` mode writes nothing and fails on a missing, changed, or unexpected
schema. The distribution check requires one wheel copy under
`crypto_lab/schemas/` and one sdist copy under `schemas/`, with bytes identical
to the reviewed source, and rejects every unexpected payload beneath either
schema prefix.

### The closed 35-file registry

`SCHEMA_DEFINITIONS` holds the eleven Stage 3 entries first, in their original
order, then the nine Stage 4 entries, then the seven Stage 5 entries, then the
eight Stage 6 protocol entries, in this order:

| # | Path | `$id` |
|---|---|---|
| 12 | `schemas/strategy/strategy-spec-v1.schema.json` | `urn:crypto-lab:schema:strategy:strategy-spec:1.0.0` |
| 13 | `schemas/strategy/strategy-version-v1.schema.json` | `urn:crypto-lab:schema:strategy:strategy-version:1.0.0` |
| 14 | `schemas/strategy/expression-v1.schema.json` | `urn:crypto-lab:schema:strategy:expression:1.0.0` |
| 15 | `schemas/capabilities/capability-requirement-v1.schema.json` | `urn:crypto-lab:schema:capabilities:capability-requirement:1.0.0` |
| 16 | `schemas/capabilities/capability-declaration-v1.schema.json` | `urn:crypto-lab:schema:capabilities:capability-declaration:1.0.0` |
| 17 | `schemas/capabilities/approximation-declaration-v1.schema.json` | `urn:crypto-lab:schema:capabilities:approximation-declaration:1.0.0` |
| 18 | `schemas/capabilities/compatibility-result-v1.schema.json` | `urn:crypto-lab:schema:capabilities:compatibility-result:1.0.0` |
| 19 | `schemas/capabilities/runtime-availability-observation-v1.schema.json` | `urn:crypto-lab:schema:capabilities:runtime-availability-observation:1.0.0` |
| 20 | `schemas/capabilities/comparison-eligibility-result-v1.schema.json` | `urn:crypto-lab:schema:capabilities:comparison-eligibility-result:1.0.0` |
| 21 | `schemas/experiments/experiment-spec-v1.schema.json` | `urn:crypto-lab:schema:experiments:experiment-spec:1.0.0` |
| 22 | `schemas/experiments/experiment-record-v1.schema.json` | `urn:crypto-lab:schema:experiments:experiment-record:1.0.0` |
| 23 | `schemas/experiments/engine-run-record-v1.schema.json` | `urn:crypto-lab:schema:experiments:engine-run-record:1.0.0` |
| 24 | `schemas/experiments/command-invocation-record-v1.schema.json` | `urn:crypto-lab:schema:experiments:command-invocation-record:1.0.0` |
| 25 | `schemas/experiments/retry-policy-v1.schema.json` | `urn:crypto-lab:schema:experiments:retry-policy:1.0.0` |
| 26 | `schemas/experiments/retry-decision-record-v1.schema.json` | `urn:crypto-lab:schema:experiments:retry-decision-record:1.0.0` |
| 27 | `schemas/experiments/experiment-aggregation-result-v1.schema.json` | `urn:crypto-lab:schema:experiments:experiment-aggregation-result:1.0.0` |
| 28 | `schemas/protocol/bootstrap-descriptor-envelope-v1.schema.json` | `urn:crypto-lab:schema:protocol:bootstrap-descriptor-envelope:1.0.0` |
| 29 | `schemas/protocol/negotiation-result-v1.schema.json` | `urn:crypto-lab:schema:protocol:negotiation-result:1.0.0` |
| 30 | `schemas/protocol/adapter-command-request-envelope-v1.schema.json` | `urn:crypto-lab:schema:protocol:adapter-command-request-envelope:1.0.0` |
| 31 | `schemas/protocol/protocol-event-envelope-v1.schema.json` | `urn:crypto-lab:schema:protocol:protocol-event-envelope:1.0.0` |
| 32 | `schemas/protocol/run-event-v1.schema.json` | `urn:crypto-lab:schema:protocol:run-event:1.0.0` |
| 33 | `schemas/protocol/adapter-validation-result-v1.schema.json` | `urn:crypto-lab:schema:protocol:adapter-validation-result:1.0.0` |
| 34 | `schemas/protocol/adapter-result-manifest-v1.schema.json` | `urn:crypto-lab:schema:protocol:adapter-result-manifest:1.0.0` |
| 35 | `schemas/protocol/sanitized-adapter-result-manifest-v1.schema.json` | `urn:crypto-lab:schema:protocol:sanitized-adapter-result-manifest:1.0.0` |

Existing entries are never reordered and a published `$id` is never reused: the
registry order is the generation order and the identifier is a permanent
contract.

**Generated bytes are reviewed source.** `schema-generate-write` produces them,
but every byte is read by hand before it is committed and is asserted against
the registry render by `tests/unit/test_schema_registry.py`. A generated file is
never hand-edited; a wrong byte is corrected in the model and regenerated.

**The eleven Stage 3 schemas are frozen.** Stage 4 leaves them byte-identical to
`main`. No test reads `main`, and none should — an ordinary test must not depend
on the branch it runs from, or on Git being installed. What the tests prove is
three-way agreement between the bytes on disk, the live registry render, and
eleven literal SHA-256 digests pinned in `tests/unit/test_schema_registry.py`,
keyed on the eleven known relative paths rather than on a count. Equality with
`main` is established once, by review, when a digest is written down; the tests
then hold the tree to those digests.

The digests are the load-bearing proof, because the other two move together:
changing a Stage 3 model and regenerating satisfies both, while a released `$id`
silently changes meaning. Two of the eleven already had an independent anchor
before Stage 4 — `tests/unit/domain/test_domain_descriptors.py` pins
`protocol/adapter-descriptor-v1` and `protocol/engine-descriptor-v1` by literal
digest, recorded at the Task 6 base commit to make the relocation's byte-identity
gate executable. The other nine had none, and now do.

Any change to one of these eleven files requires an independently approved
architecture correction that owns it.

**The nine Stage 4 schemas are frozen in the same way, and Stage 5 leaves all
twenty earlier files byte-identical.** The `_STAGE3_SHA256` and `_STAGE4_SHA256`
blocks in `tests/unit/test_schema_registry.py` are re-verified against both the
live render and the committed files in the Stage 5 tree, the seven new files are
pinned alongside them in `_STAGE5_SHA256`, keyed on the seven known relative
paths, and the two digest blocks of the earlier stages are asserted disjoint from
the Stage 5 paths. Registering seven entries changed none of the twenty published
byte sequences, which is what makes the Stage 1 relocations of `RetryTerminalState`
and `CompatibilityOutcome` verifiably byte-neutral.

**The seven Stage 5 schemas are frozen in the same way, and Stage 6 leaves all
twenty-seven earlier files byte-identical.** The `_STAGE3_SHA256`,
`_STAGE4_SHA256` and `_STAGE5_SHA256` blocks in
`tests/unit/test_schema_registry.py` are re-verified against both the live
render and the committed files in the Stage 6 tree, the eight new files are
pinned alongside them in `_STAGE6_SHA256`, keyed on the eight known relative
paths, and the three earlier digest blocks are asserted disjoint from the
Stage 6 paths. Registering eight entries changed none of the twenty-seven
published byte sequences. Three of the eight are temporary token-bearing wire
contracts (`adapter-command-request-envelope` through its run payload,
`protocol-event-envelope` and `adapter-result-manifest`): they describe what an
adapter reads or writes, are trust class W and are never persisted; `run-event`
and `sanitized-adapter-result-manifest` are the core-preserved forms and carry
only `attempt_token_hash`; `bootstrap-descriptor-envelope`,
`negotiation-result` and `adapter-validation-result` are token-free by contract.

### Stage 4 timestamp projections

Every timestamp field reachable from the published Stage 4 schema graph uses the
calendar- and clock-valid forward schema view. That view is additive over the
released Stage 3 projection: it keeps the fractional-second grammar, the
uppercase `Z`, and the exact end-of-string assertion, and adds a pinned
Gregorian date prefix and a clock-range branch. Published Stage 4 bytes
therefore reject year `0000`, February 30, April 31, a non-leap-century February
29 such as `2100-02-29`, hour `24`, minute `60`, and second `60`, while
accepting every real instant the runtime accepts, including `0004-02-29`,
`2000-02-29`, and `9999-12-31T23:59:59Z`.

The three released Stage 3 `$id`s — `domain/diagnostic-v1`,
`datasets/dataset-partition-v1`, and `datasets/dataset-descriptor-v1` — keep the
original, more permissive date grammar. That is a deliberate frozen residual,
not an oversight: their bytes are published contract.

`Bar` is a Stage 4 model that is deliberately **not** registered. It has no
`$id` and appears in no registered adapter's reachable `$defs`, so its
timestamp annotation publishes nothing. Registering it later requires an
explicit timestamp decision, which the guards in
`tests/unit/test_schema_registry.py` and `tests/unit/domain/test_time.py` force
rather than assume.

### Stage 5 timestamp projections

Every timestamp field reachable from the seven Stage 5 schemas --
`created_at_utc`, `updated_at_utc`, `deadline_utc`, `launch_attempted_at_utc`,
`process_started_at_utc`, `completed_at_utc`, `cleanup_completed_at_utc`,
`finalization_deadline_utc`, `retry_not_before_utc` and `decided_at_utc` -- uses
the same calendar- and clock-valid forward view as Stage 4. The registry half of
`test_every_published_stage_four_timestamp_uses_the_forward_view` in
`tests/unit/domain/test_time.py` iterates every non-Stage-3 registry entry in both
generation modes, so it covers the seven Stage 5 entries without modification, and
the Stage 5 contract tests reject `2026-02-30T00:00:00Z`, `2026-01-01T24:00:00Z`
and a naive instant against the committed bytes. The Stage 5 records, requests
and the retry decision are stamped only from the injected `Clock`; no Stage 5
module reads a wall clock, which `tests/safety/test_stage5_boundaries.py`
enforces statically.

### Stage 6 timestamp projections

Every timestamp field reachable from the eight Stage 6 schemas --
`created_at_utc` and `deadline_utc` on the request envelope and `created_at_utc`
on its run payload, `timestamp_utc` on the event envelope, `timestamp_utc` and
`received_at_utc` on the sanitized `RunEvent`, `validated_at_utc` on the
validation result, and `started_at_utc` and `completed_at_utc` on both
manifests -- uses the same calendar- and clock-valid forward view as Stages 4
and 5, rendered byte-identically in every file that carries it. The registry
half of `test_every_published_stage_four_timestamp_uses_the_forward_view` covers
the eight entries without modification; the bootstrap envelope and the
negotiation result carry no timestamp. The Stage 6 contract tests reject
`2026-02-30T00:00:00Z`, `2026-01-01T24:00:00Z`, `2026-04-31T00:00:00Z` and a
naive instant against the committed bytes. Every Stage 6 instant is stamped
from the injected `Clock`; no Stage 6 module reads a wall clock, which
`tests/safety/test_stage6_boundaries.py` enforces statically over the fourteen
Stage 6 modules.

### The published expression dispatcher

`$defs/Expression` is a closed twenty-one-member union, and it is published as
standard Draft 2020-12 **conditional dispatch** rather than as a recursive
`oneOf`: a root `op` enum, and an `allOf` of twenty-one `if`/`then` clauses whose
condition tests only `op` and whose consequent is a single `$ref` to the matching
branch model. Exactly one clause per node descends into that node's children.

The recursive `oneOf` it replaced was exponential in tree depth, and the
published bytes were the worst case rather than the best: canonical key sorting
places a branch's recursive `left` ahead of its discriminating `op`, so even
`oneOf`'s short-circuiting post-match scan recursed into children; and later
same-shape binary branches were exponential even unsorted, because every earlier
branch recursed before the matching one was reached. Conditional dispatch
removes both mechanisms — an `if` cannot see a child at all, and only the
matching `then` recurses.

**Cost is now linear in document size rather than exponential in depth. It is
linear in *size*, though, and the depth bound does not bound size.** A depth-24
chain is a 47-node spine of about 1.8 KB and decides in tens of milliseconds. A
*complete* binary tree is exponentially larger at the same depth, and
`MAX_EXPRESSION_DEPTH` admits it. Measured against the published bytes:

| shape | expression nodes | JSON bytes | seconds |
|---|---|---|---|
| depth-24 chain | 47 | 1,814 | 0.02 |
| complete depth 12 | 4,095 | 157,662 | 1.7 |
| complete depth 13 | 8,191 | 315,358 | 3.5 |
| complete depth 14 | 16,383 | 630,750 | 8.4 |
| complete depth 15 | 32,767 | 1,097,699 | tens of seconds |

Throughput is about thirteen microseconds per byte, steady across four orders of
magnitude. The ten-second figure the tests assert is a hang detector over the
depth-24 representatives; it is **not** a bound on every admissible document, and
a complete tree at depth 14 already reaches it.

**The loader's bounds do not contain this, and an earlier draft of this document
wrongly said they did.** `StrategyLoader` rejects a source over
`MAX_SOURCE_BYTES` (262,144) before parsing, and the single-pass builder caps
expanded nodes at 50,000 and events at 20,000 — but 50,000 admits the
32,767-node tree above, and alias expansion is precisely the mechanism that turns
a small source into a large document, which is why that budget exists at all. So
the loader constrains the *source*, not the validation cost of the resulting
document.

The practical consequence: any consumer that validates an untrusted strategy
document against these published schemas should bound node count or document
size itself. The schema is a shape contract and carries no such bound, and
neither the depth bound nor the loader's source bound substitutes for one. The
runtime Pydantic validation is unaffected — it stays sub-millisecond — so this is
a statement about third-party JSON Schema validation, not about this project's own
loading path.

The `discriminator` annotation is retained verbatim for tooling. It is **not**
the basis of validation: Draft 2020-12 ignores it, and
`tests/unit/test_schema_registry.py` asserts that stripping it changes no
verdict. The dispatcher root deliberately carries no `additionalProperties`,
because closing a root that names only `op` would reject the `left`, `right`,
`operand`, and `operands` fields the branch models own; field closure lives on
each branch model, every one of which is closed.

### Runtime rules the published schema cannot express

Draft 2020-12 expresses a rule exactly when the discriminating or key domain is
closed, finite, and small enough to enumerate. Where it is not, the rule stays a
runtime validator and is recorded here rather than approximated in the published
bytes.

Two classes of rule are **out of scope** for this register rather than missing
from it. Loader-level rules — expression reference integrity, feature-graph
acyclicity, and warm-up sufficiency — are enforced by `StrategyLoader`, not by
the registered models, so a published record schema is not the artifact that
should carry them. And the eleven Stage 3 schemas are frozen released bytes; any
residual in them is preserved deliberately and is not Stage 4's to close.

The Stage 4 register:

- expression-tree depth (`MAX_EXPRESSION_DEPTH`), because the schema is
  recursive and a faithful encoding would require unrolling every level;
- sortedness of a collection whose element domain is unbounded, such as
  `CapabilityDeclaration.limitations`. Where the domain **is** closed and
  finite — `comparison_levels` and `prevented_comparison_levels`, three members
  each and bounded at three items — sortedness is published exactly, as the
  closed set of eight sorted arrays;
- key-based uniqueness, where the runtime deduplicates on a designated key
  rather than on the whole item. A flat `uniqueItems` does not express that, and
  it is not claimed to. Of the sixteen published Stage 4 positions that carry
  `uniqueItems`, twelve are exact — whole-value equality is the runtime rule for
  `CapabilityRequirement.comparison_levels`,
  `ApproximationDeclaration.prevented_comparison_levels`,
  `CapabilityDeclaration.limitations`, `Universe.instruments`,
  `CompatibilityResult.reasons`, `ComparisonEligibilityResult.reasons`, and
  `ComparisonEligibilityResult.declared_differences` — and four are a sound but
  partial tightening, where the runtime key is narrower than the whole item:
  `CompatibilityResult.approximations`, `ComparisonInput.approximations`,
  `ComparisonInput.assumptions`, and `ComparisonInput.declared_differences`.
  Both halves are pinned by exact pointer, so a field cannot move between them
  silently.

  Of those four, only the two `approximations` positions are a residual. Their
  key is `capability`, a pattern-constrained identifier with no closed domain, so
  no exact encoding exists. The other two are **not** residuals at all: the same
  schema already publishes their rules exactly, in
  `/$defs/ComparisonInput/allOf`, as twenty-eight `contains` clauses with
  `minContains`/`maxContains` — one per member of the closed fourteen-member
  `ComparisonMaterial` and `DifferenceCategory` enums. That encoding is exact
  because those domains are closed and small: `assumptions` is total at exactly
  one entry per material, and `declared_differences` admits at most one per
  category. `uniqueItems` at those two positions is redundant reinforcement
  rather than the enforcement mechanism, and
  `test_comparison_input_publishes_its_key_uniqueness_exactly` pins the clauses
  so they cannot be dropped silently;

  **The repository is not consistent here, and the inconsistency is published.**
  Six Stage 4 collections carry a key-based runtime rule. Four of them publish
  `uniqueItems` as the partial tightening described above.
  `StrategySpec.required_capabilities` and `StrategySpec.engine_extensions`
  publish nothing, although their runtime validators reject an exact whole-value
  repeat and `uniqueItems` would express that subset without over-rejecting
  anything. Those two are therefore weaker in the published bytes than the other
  four, for no principled reason — both convention and its absence ship side by
  side. Closing it edits `src/crypto_lab/strategy/models.py`, which Stage 4
  Task 2 owns and which is outside the file map of the task that generated these
  schemas, so it is recorded here as a known gap and escalated rather than
  silently fixed or silently omitted;
- comparisons between two values carried by the same document, such as a
  `ParameterDefinition` bound against its value or
  `RuntimeAvailabilityObservation.expires_at_utc` against its `observed_at_utc`.
  Draft 2020-12 has no cross-field comparison, and this holds for the integer
  cases as much as the Decimal-string ones;
- `StrategyVersion.validate_identity_is_recomputed`, which requires recomputing
  the SHA-256 strategy identity over canonical bytes and comparing it with the
  recorded `content_hash`. Nothing in Draft 2020-12 computes a digest, so every
  rule in that validator — the content hash, the recorded extension hashes, and
  the derived version identifier — is a runtime-only residual;
- the **spelling** of an integer. Draft 2020-12 defines `type: "integer"` as any
  number with a zero fractional part and offers no keyword for lexical form, so a
  published integer field cannot accept `0` while rejecting `0.0`, `1e1`, or
  `-0.0`. The strict runtime rejects all three. `bars_ago` and an `INTEGER`
  literal `value` are the reachable cases. The published bytes are a strict
  superset here, which is the safe direction — no document the runtime accepts is
  rejected — and the divergence is pinned by
  `test_the_integer_spelling_residual_stays_one_directional` so it cannot widen,
  or invert into an over-rejection, unnoticed;
- an **unpaired surrogate escape** in any published string — `\ud800` or
  `\udc00` without its partner, reachable through `evidence_note`,
  `limitations`, `method`, `expected_impact`, `executable_path`, and a `STRING`
  literal `value`. This one is not a weakness in the schema at all: the two
  parsers disagree about what counts as JSON. Python's `json` module accepts a
  lone surrogate, so a schema validator built on it accepts the document, while
  pydantic-core's parser refuses it outright with `json_invalid`. Draft 2020-12
  has no keyword that constrains escape-sequence pairing, so the rule is not
  expressible even in principle. A correctly paired astral character agrees on
  both sides. The direction is again the safe one.

A large body of exactly expressible rules *is* published, and the tests assert
each against the committed bytes on disk rather than against a live render: the
four compatibility-outcome cardinalities, state-governed optionality on
`reason_code` and `achieved_level`, the closed error-code and capability sets at
the field rather than on the shared types, `market_type` fixed to `SPOT`,
`direction` fixed to `LONG`, `leverage` fixed to `"1"`, the
`ParameterDefinition` value-type agreement rule, the `bars_ago` bounds, and the
`executable_path` whitespace and control-character rule. Each negative table in
`tests/unit/test_schema_registry.py` is paired with an accepting baseline, so a
rejection can never be an artifact of an already-invalid document, and every
committed strategy fixture is accepted through the loader against the shipped
bytes.

**What is deliberately not claimed.** Earlier drafts of this document asserted
that *everything* exactly expressible is published, and that a generated sweep
had established the register above is complete. Neither claim survived review.

The first is false: the two collections named in the key-based bullet have an
expressible subset that is not published. The second overstated its evidence. Two
independent sweeps were run at the Stage 4 implementation commit — one by the
implementer, one by a reviewer working from a harness built without reading it.
Both agree on the strong, falsifiable results: **zero over-rejections** and
**zero disagreements between the four schema surfaces** (both generation modes,
the registry render, and the parsed bytes on disk), each over a corpus whose
baselines are all accepted by every surface. They do **not** agree on the
residual set. The implementer's sweep produced no under-rejection at all from any
of the six `capabilities/*` schemas and resolved to three runtime rules; the
reviewer's produced forty-six under-rejections resolving to eleven, ten of which
fall inside this register and one of which is the unpublished tightening above.

So: the register is a maintained enumeration, not a machine-verified closure, and
the number of *rules* either sweep found is a lower bound. What the sweeps
establish is the direction of every divergence — the published bytes are a
superset of the runtime, never a subset — which is the property that matters for
a consumer. Both measurements are recorded in the stage ledger. Re-derive rather
than cite them if a later stage changes a published Stage 4 record.

### Runtime rules the Stage 5 schemas cannot express

The seven Stage 5 schemas publish every closed enumeration member by member
(`ExperimentState`, `EngineRunState`, `CommandInvocationState`, `CommandKind`, the
eight-member `ProcessExitCategory`, `RetryTerminalState`, `RetryDecisionOutcome`,
`RetryDenialReason`, `AggregationVerdict`, `CompatibilityOutcome` and the four
execution vocabularies), every numeric bound (`attempt_number` and
`created_attempt_count` 1..5, `reserved_successor_attempt_number` 2..5,
`maximum_attempts_per_slot` 1..5, `retry_delay_seconds` 0..300, `slot_ordinal`
0..7, precisions 0..18, `pid` 1..4294967295, `native_exit_value` in the signed
and unsigned 32-bit span, `timeout_seconds` 1..604800), every collection bound
and whole-value `uniqueItems` (nine positions, all exact), every required field
set in declaration order, `additionalProperties: false` on every object, and the
`ROUND_HALF_EVEN` and fixed-`true` literals. `tests/unit/test_schema_registry.py`
asserts each against the committed bytes with an accepting baseline the runtime
itself produced, and 34 such baselines round-trip through the schema and the
runtime.

What stays runtime-only is pinned in the other direction by
`test_the_stage_five_runtime_only_rules_stay_one_directional`: eighteen documents
that the published bytes accept and the runtime rejects, so the published bytes
remain a superset of the runtime and a residual cannot silently invert into an
over-rejection or widen unnoticed. The register:

- state-governed presence: `slot_compatibility` (absent before `QUEUED`) and
  `cancellation_correlation_id` (present exactly in `CANCELLED`) on
  `ExperimentRecord`; `predecessor_run_id` and `retry_reason` (present exactly on a
  successor attempt), `primary_terminal_diagnostic_id` (present exactly in the
  five non-success terminals) and `availability_observation_id` on
  `EngineRunRecord`; the eight-row field-shape table, the launch, process, exit
  and cleanup co-occurrence pairs and the terminal partition on
  `CommandInvocationRecord`; the outcome-governed fields, the precedence filter
  and `reserved_successor_attempt_number = created_attempt_count + 1` on
  `RetryDecisionRecord`. Draft 2020-12 can express state-governed presence with
  `if`/`then`, but every such rule lives in a Task 2-5 domain model outside Task
  9's file map, so none is published and each is recorded here;
- `finalization_deadline_utc` on `EngineRunRecord`: published as an optional
  property that the Stage 5 runtime always rejects (plan section 3.8 row 15), so
  Stage 9 can snapshot it without changing the published `$id`;
- `RetryDecisionRecord.predecessor_terminal_state` publishes the full
  twelve-member `EngineRunState` and the runtime narrows it to the five
  non-success terminals (plan section 3.9);
- the frozen `process_exit_category = f(native_exit_value)` mapping and the
  command-kind-specific `timeout_seconds` bound: both exactly expressible as small
  closed `if`/`then` tables and both unpublished for the same file-map reason,
  recorded as a known gap rather than silently approximated;
- `spec_hash` recomputation, `deadline_utc = launch_attempted_at_utc +
  timeout_seconds`, `updated_at_utc >= created_at_utc`, `predecessor_run_id !=
  run_id` and `primary_diagnostic_id` membership in `diagnostic_ids`: comparisons
  between two values of one document, inexpressible;
- sortedness of `approximation_ids`, `diagnostic_ids`, `reason_codes` and the
  selected-slot ordinals, whose element domains are unbounded; and the fixed
  `FAILED`, `TIMED_OUT`, `UNAVAILABLE` order of `automatically_retry_terminal_states`,
  which the runtime normalizes rather than rejects and which is expressible as the
  closed set of eight arrays but unpublished for the file-map reason;
- `slot_compatibility` carries no item bound because its runtime bound is
  alignment with the selected slots, and the inlined released `Money` schema
  admits a non-positive `starting_balance` that the enclosing record rejects;
  the released `domain/money-v1` bytes are frozen.

### Runtime rules the Stage 6 schemas cannot express

The eight Stage 6 schemas publish every closed enumeration member by member
(`SemanticStatus`, `ValidationOutcome`, `ProtocolEventType`,
`NegotiationOutcome`, `AdapterDiagnosticCategory`, `CommandKind`,
`DiagnosticSeverity`, `ComparisonLevel`, `OperatingSystem` and, through the
request envelope's configuration snapshot, `SlippageModel`,
`SignalToOrderTiming`, `BarOrderPriority` and `FillConvention`), every numeric
bound (`sequence` 1..1000000, `attempt_number` 1..5, `timeout_seconds`
1..604800 with the per-command maxima 300, 1800 and 604800, the protocol limit
floors and ceilings, the 53-bit counters and sizes), every collection bound and
whole-value `uniqueItems` (forty positions: thirty-six exact and four
key-based partial tightenings recorded below), every identifier prefix
and SHA-256 shape, the reserved-device-stem and trailing-dot rules of the
relative candidate path grammar, the adapter-namespace prefix of every
`error_code` and `warning_code`, every required field set in declaration order
and `additionalProperties: false` on every object.
`tests/unit/test_schema_registry.py` asserts each against the committed bytes
with accepting baselines the runtime itself produced: 33 documents built through
the committed builders and parsers and 21 captured from the fake adapters' own
outputs of the first three contract rows (the describe output, the request
envelope files, the raw stdout lines, the stored `RunEvent`s, the validation
output, the manifest file and the reconciled sanitized manifest), 54 in all,
each round-tripping through the schema and the runtime.

The cross-field rules Draft 2020-12 can express are published as shallow
`if`/`then` clauses and are therefore exact in both directions: the
`NEGOTIATED`/`FAILED` biconditionals over `outcome` (selected values present
exactly when negotiated, at least one reason code exactly when failed); the
command-to-payload pairing and the per-command `timeout_seconds` maximum on the
request envelope; the event-type-to-payload pairing on both the wire envelope
and the sanitized `RunEvent`; `value_status` `DEFINED` exactly when `value` is
present; `SUCCEEDED` with no warning, `SUCCEEDED_WITH_WARNINGS` with at least
one, and every non-success status with at least one diagnostic and no candidate
on both manifests; a non-`VALID` validation outcome with at least one
diagnostic; and `ResourceObservation` with at least one field present. The
exact five negotiable schema names by position are published as `prefixItems`.

What stays runtime-only is pinned in the other direction by
`test_the_stage_six_runtime_only_rules_stay_one_directional`: 28 documents that
the published bytes accept and the runtime rejects, so the published bytes
remain a superset of the runtime and a residual cannot silently invert into an
over-rejection or widen unnoticed. The register:

- hash recomputation, inexpressible: `descriptor_payload_hash`,
  `payload_hash`, `request_hash`, `content_hash`, `result_hash` and
  `sanitized_adapter_result_manifest_hash`; `wire_event_hash` is provenance the
  runtime does not recompute and is deliberately not a residual;
- comparisons between two values of one document: the bootstrap header
  mirroring its nested descriptor and the descriptor's vocabulary being among
  the declared vocabularies; a selected protocol version being a candidate;
  `payload.request_id == request_id`, `comparison_level ==
  configuration_snapshot.comparison_level` and `deadline_utc == created_at_utc
  + timeout_seconds` on the request envelope; `total_units >= completed_units`;
  `completed_at_utc >= started_at_utc`; and `candidate_artifact_ids` equal to
  the declaration identities;
- the missing-heartbeat threshold at least twice the heartbeat interval, the
  positive `starting_balance` on the shared released `Money` schema, and
  `ProgressPayload.percentage <= 100` on a decimal string;
- sortedness of collections whose element domains are unbounded or numeric:
  `approximations`, `causal_event_ids`, `reason_codes`, and the numerically
  sorted version tuples of the bootstrap envelope, the negotiation result and
  the describe payload's `core_supported_protocol_versions` on the request
  envelope (lexically sorted strings pass the bytes);
- uniqueness of declarations on `relative_path` and of metrics on
  `metric_name`, published as whole-value `uniqueItems`, a sound partial
  tightening; and
- the recursive `DiagnosticDetailValue`: the published bytes bound each level
  (64 keys or items, 2048-character strings, 64-bit integers) and the runtime
  additionally bounds the total depth and node count.

Declared readings recorded with the register: `NegotiationResult.reason_codes`
is the deviation from specification 11.3's field name `diagnostics`; the
`RUN_EVENT_CONTENT_V1` hashing profile excludes `received_at_utc` and
`wire_event_hash`, which is what makes the replay rule satisfiable; the
canonical value forms an adapter must emit for the stdlib-reproducible hashes
are the canonical JSON rules; adapter diagnostics are cited from core
diagnostics through `details`, not `causal_diagnostic_ids`; the describe member
of `CommandResult.parsed_output` is the bootstrap envelope, not the bare
descriptor; and `list_events` is a declared port extension.

Schema tractability is measured on the committed bytes in a bounded child
process over a 31-document matrix (every dispatch branch, the wrong branch and
an unknown discriminator on the three dispatching schemas, the recursive
detail value at depth eight and breadth 64 with an invalid leaf at the deepest
point, and both manifests at their widest bounded breadth with an invalid
value at the deepest position): every verdict is the expected one under a
coarse hang ceiling, and the cost per byte stays linear. The measurements are
recorded in the stage ledger; re-derive rather than cite them if a later stage
changes a published Stage 6 record.

## Explicit configuration

Configuration sources are compiled defaults, an explicitly named primary TOML
file, an optional explicitly named local-override TOML file, and allowlisted
typed CLI overrides in that precedence order. No environment-variable layer,
profile discovery, home-directory lookup, current-directory lookup, registry
lookup, directory scan, credential source, or implicit file is permitted.

## Dependency changes

Do not hand-edit `uv.lock`. After an approved `pyproject.toml` dependency
change:

1. Run launcher profile `lock-resolve-offline`.
2. If cached registry metadata alone is absent, stop, show exact launcher
   profile `lock-acquire`, and obtain one-time approval before running it.
3. Validate with the launcher `lock-check` operation.
4. Run the launcher `sync` operation.
5. If distributions alone are absent, stop, show the exact
   `sync-acquire` launcher profile, and obtain one-time approval.
6. Return to both ordinary offline commands.
7. Commit `pyproject.toml` and generated `uv.lock` together.

No dependency operation may install an engine, exchange client, networking
client, or GitNexus. SQLAlchemy and Alembic are the only permitted direct
database-stack dependencies. Their acquisition is subject to the approved
SQLite persistence gates; ordinary verification remains offline.
GitNexus remains disabled with evidence and outside product, test, build,
runtime, verification, and acceptance paths.

## Stage scope

Project 1 Stage 7 is complete. Shell-free absolute argument-array launch with
a fresh empty environment, bounded stdout and stderr readers, incremental
protocol parsing, paired UTC and monotonic deadlines, heartbeat liveness,
graceful and forced termination with Job Object process-tree cleanup, durable
PID creation identity, path preflight, stale-invocation rejection, and
restart reconciliation are implemented. Stage 7 implementation completed at
`c1b17e481e9e1c192d4cae0a70764bf4d643515a`; the Stage 7 boundary guard and
this status were added by the separate Task 9 commit, which is not the
implementation hash. No schema was added: the closed 35-schema registry is
preserved byte-identical. The fake adapters run through the production
supervisor as well as the test-resident stand-in. Stage 8 is not started.

The independent sweeps agree on the falsifiable results: zero
over-rejections, and zero disagreement between the four schema surfaces.
The published bytes are therefore a superset of the runtime, never a
subset. The two sweeps do not agree on the residual set of inexpressible
rules, and that register is a maintained enumeration rather than a
machine-verified closure, not a claim that every possible runtime or
schema rule was exhaustively enumerated.

GitNexus remains `DISABLED_WITH_EVIDENCE` and is non-blocking: it is not
required to set up, verify, build, test, or run the project, and it is not
invoked by any verification gate. The manual source, reference, and diff
fallback is the recorded workflow.

No real trading engine, exchange connectivity, market-data download, real
backtest, order or fill simulation, portfolio accounting, persistence, paper
wallet, tax or TDS logic, LLM integration, user interface, Docker setup, cloud
deployment, or server deployment exists anywhere in the repository. Stage 4
executes no engine, no adapter, no strategy, and no declared engine extension,
and combines no comparison result into an averaged, voted, or synthetic figure.

Stage 5 launches no process, executes no adapter or engine, opens no database or
file, persists nothing outside in-memory test doubles, and contacts no network.
Its retry decisions and aggregation verdicts are deterministic functions of
recorded facts and the injected clock, never of a wall clock or a random source,
and `tests/safety/test_stage5_boundaries.py` enforces every one of those
exclusions statically over the source tree.

Stage 6 launches only the executable fake adapters, as child processes of the
test-resident offline harness; it opens no database, contacts no network,
persists nothing outside in-memory test doubles, treats every adapter output as
untrusted until reconciled, redacts every raw attempt token before a core record
exists, and commits no success run state.
`tests/safety/test_stage6_boundaries.py` enforces the fourteen Stage 6 modules'
exclusions statically, pins the exact four classes that may carry a raw-token
field, the eleven `subprocess` importers (the ten of Stage 6 and the Stage 7
fake script) and the no-shell rule over the whole test tree, and records the
roadmap's Stage 6 completion.

Stage 7 launches the same executable fake adapters, and its own Stage 7 fake
script, through the production `WindowsProcessSupervisor` over the real
`WindowsProcessController` as well as through the stand-in: every command root
lives under pytest's temporary directory, every launch is an absolute executable
with an exact argument array, no shell and an empty environment block, and every
real-process test ends in a `finally:` that terminates the identities it
launched or recorded and asserts that none of them is still alive under its
recorded creation identity. It opens no database, contacts no network, persists
nothing outside in-memory test doubles, finalizes no artifact, creates no
`RunManifest`, and commits no success run state.
The Windows controller keeps a Toolhelp candidate as a descendant only when
its creation time is not earlier than its parent's recorded creation time, so
a stale parent process identifier that now names a newer process is excluded
while a creation in the same clock tick is admitted.
`tests/safety/test_stage7_boundaries.py` pins the twelve Stage 7 source modules,
confines the five Stage 7 import roots to their named modules, scans the one
`Popen` call in the source tree, pins the Stage 7 fake script's import surface,
and records the roadmap's Stage 7 completion. Measured on one host during the
Stage 7 implementation, the seven Stage 7 Windows platform modules take about 42
seconds of pytest time and the supervised matrix about 50 seconds, and the
stdout-flood row states its own 120-second deadline because each accepted event
costs the supervision thread a few milliseconds; both figures are recorded in
the stage ledger and should be re-derived rather than cited. One limitation is
recorded rather than hidden, and one corrected test-hygiene defect is recorded
rather than erased. Under coverage tracing a large post-exit stdout backlog
can outlast the pipe-holder grace window, so the pipe-holder rule may fire
once on an already-reaped root and add a `PROCESS.FORCED_TERMINATION`
diagnostic to an otherwise clean flood; the kill finds no live process and the
invocation still reaches `EXITED` with its exit facts, the flood row pins that
bounded shape, and the correction is recorded in the stage ledger as an open
note against the supervisor. Separately, and now closed: before the
completion commit, the job-less grandchild tests of the Windows controller
unit module ended a launcher by process identifier inside the launcher's own
create-suspended-then-resume window, which under host load left never-resumed
suspended interpreter children that no `finally:` assertion covered, and two
complete-verifier runs leaked such fixture orphans. The test-only commit
`e9bcd8e19563f6ececdf5f683a561cdf36caa712` corrected those tests: before any
destructive action a job-less test waits for a line its child prints only
once its interpreter is running (the child's own `ready` line, or the process
identifier a spawner prints only after its own sleeper's `ready`) or for the
child's own exit, ownership is process identifier plus creation identity for
the launcher and every recorded descendant, and the fixture cleanup requires
every owned identity to be absent. The stage ledger records zero task-owned
survivors (processes running the project interpreter with a fixture program
on their command line) and zero suspended fixture processes on every covered
run since, including the complete verifier alone on the corrected tree and on
merged `main`. That closed fixture defect is distinct from the host-timing
facts that remain recorded: the pipe-holder note above stays open against the
supervisor, and a host that signals a terminated process object only after
the production post-termination bound is accepted by those tests as the
bounded `TREE_VERIFIED_DEAD` report, never as a leak. Verification is
required to be leak-free: a run that leaves a task-owned process or a Stage 7
command root behind (pytest's own retained base temporary directories are
neither) is not acceptance evidence whatever its exit status, and the stage
ledger records the process probes taken around every long run.
