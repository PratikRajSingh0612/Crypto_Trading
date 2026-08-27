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
generation checks the closed 20-file registry without writing; distribution
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
generator targets only the 20 fixed lexical descendants, rejects an existing
symlink root or entry, and refuses every unexpected file without deleting it.
Stage 7 retains physical ancestor reparse-point and volume containment. The
`--check` mode writes nothing and fails on a missing, changed, or unexpected
schema. The distribution check requires one wheel copy under
`crypto_lab/schemas/` and one sdist copy under `schemas/`, with bytes identical
to the reviewed source, and rejects every unexpected payload beneath either
schema prefix.

### The closed 20-file registry

`SCHEMA_DEFINITIONS` holds the eleven Stage 3 entries first, in their original
order, followed by the nine Stage 4 entries in this order:

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
client, database stack, or GitNexus. GitNexus remains disabled with evidence
and outside product, test, build, runtime, verification, and acceptance paths.

## Stage scope

Stage 4 implementation is complete and awaits Task 9 final status recording and
whole-stage completion review. Stage 5 is not started.

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
