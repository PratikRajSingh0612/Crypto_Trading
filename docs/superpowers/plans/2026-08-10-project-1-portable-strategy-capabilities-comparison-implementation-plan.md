# Project 1 Portable Strategy, Capabilities, and Comparison Implementation Plan

**Status:** Approved for Project 1 Stage 4 implementation
**Stage:** 4 of 10
**Planning base commit:** `e1c821453459f5eccf86a472e9204b6a90829d64`
**Correction base commit:** `350fac49ff5b1db4ec62b60c7ade76580f9894dd`
**Execution prerequisites, both of which must be ancestors of local `main`
before Stage 4 implementation begins:** the launcher bootstrap correction at
`350fac49ff5b1db4ec62b60c7ade76580f9894dd`, and the separate
roadmap-and-guard commit that records this plan's approval in roadmap section 9
and adds the executable plan-approval guard. Section 9.0 step 1 checks both by
ancestry
**Date:** 2026-08-10
**Revised:** 2026-08-15

This plan authorizes Stage 4 implementation only. It does not authorize Stage 5
or any later stage, and it does not itself change source, tests, schemas,
`pyproject.toml`, or `uv.lock`.

## 1. Goal and architecture

### 1.1 Goal

Stage 4 turns a human-authored YAML strategy document into a strictly
validated, content-addressed, engine-neutral record, and turns strategy
requirements plus one adapter descriptor into a deterministic compatibility
decision. It delivers:

1. Safe YAML source loading with project-owned bounds enforced before any
   Python object is constructed.
2. Strict `StrategySpec` contracts and an immutable `StrategyVersion` with
   source provenance.
3. A closed discriminated expression AST with static type and reference
   checking.
4. Feature DAG validation with deterministic cycle diagnostics and a stable
   topological order.
5. A pure, deterministic, fixture-sized Level 1 reference evaluator.
6. Strategy hashing that includes every declared extension-module hash.
7. A versioned capability vocabulary, requirements, declarations, and a pure
   deterministic compatibility resolver producing all four outcomes.
8. Approximation declarations, comparison levels, comparison eligibility, and
   difference classification.
9. Nine new generated canonical JSON Schemas, taking the closed registry from
   11 to 20 entries.

### 1.2 Architecture position

Stage 4 populates two previously empty packages, `crypto_lab.strategy` and
`crypto_lab.capabilities`, and adds one shared `Result` primitive to
`crypto_lab.domain`.

```text
                domain
   (canonical records, primitives, descriptors,
    comparison levels, capability names,
    capability requirements, Result)
       ^          ^              ^
       |          |              |
   strategy   capabilities    adapters
```

`domain` gains no outward dependency. `strategy` depends only on `domain`.
`capabilities` depends only on `domain` and imports **nothing** from
`adapters`. The contract types that specification section 8.2 places in the
resolver signature — `AdapterDescriptor`, `RuntimeAvailabilityObservation`, and
`ComparisonLevel` — are relocated into `domain` per section 5.7, which
specification section 27.1 requires and section 8.2 explicitly authorizes.
`adapters/descriptors.py` re-exports them, so its public surface is unchanged.

Stage 4 adds no persistence, no process launch, no filesystem access from
strategy or capability code, no network access, and no engine integration.

## 2. Normative sources

Read completely before the first edit. Authority descends in this order.

| Order | Source | Scope |
|---:|---|---|
| 1 | `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md` | Sections 8.1–8.2, 10.2, 11.1–11.5, 12, 13, 20.4, 24.1–24.4, 25, 26, 27.1–27.3, 28.1, 28.4, 33.2–33.3, 33.7 |
| 2 | `docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md` | Stage 4 row of section 4; sections 3, 5, 6, 7 |
| 3 | `docs/decisions/0001-gitnexus-development-tooling.md` | GitNexus is `DISABLED_WITH_EVIDENCE`; use the manual fallback |
| 4 | `AGENTS.md` | Repository instructions, launcher rules, safety boundaries |
| 5 | Merged Stage 3 source, tests, schemas, and launcher | Observed interfaces in section 3 |
| 6 | This plan, after independent approval | Stage 4 execution |

Reference commits:

| Fact | Commit |
|---|---|
| Stage 1 complete | `56d029e8e6d3c67dc6309b267c74833a09d2e419` |
| Stage 3 Task 7 — generated canonical schemas | `7b1d2a579020b60fc23223d51e571a71bb81b60f` |
| Stage 3 Task 8 — verification workflow | `d50744547d121d1b5925a5d92d752345902f5e56` |
| Stage 3 Task 9 — completion status | `88711307ff377e645bb17c798e599b6bac1c2be4` |
| Stage 3 implementation complete | `88711307ff377e645bb17c798e599b6bac1c2be4` |
| Stage 3 post-completion stability correction | `e1c821453459f5eccf86a472e9204b6a90829d64` |
| Stage 4 launcher bootstrap prerequisite | `350fac49ff5b1db4ec62b60c7ade76580f9894dd` |

The launcher bootstrap commit is an **execution prerequisite**, not Stage 4
work. It repaired a genuine deadlock: the launcher resolved
`.venv\Scripts\python.exe` before dispatching any operation, so a fresh
worktree could not run `sync`, which is the operation that creates `.venv`.
Section 3.8 records the corrected behaviour, and section 9.0 makes the
prerequisite an executable preflight check. Stage 4 implementation must leave
that corrected launcher unchanged.

If an authoritative requirement conflicts with another, stop before editing and
report `BLOCKED_ARCHITECTURE_CONFLICT` with exact files, headings, and the
conflicting requirements.

## 3. Observed Stage 3 interfaces

Every item below was read from merged source at
`e1c821453459f5eccf86a472e9204b6a90829d64`. Stage 4 consumes these exactly and
invents no alternative.

### 3.1 Model base and conventions

- `crypto_lab.domain.base.CanonicalModel` — Pydantic v2 `BaseModel` with
  `ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True,
  strict=True, validate_default=True)`. Module constant `SCHEMA_VERSION =
  "1.0.0"`.
- Every canonical top-level record declares `schema_version:
  Literal["1.0.0"]`.
- State-governed optionality uses
  `pydantic.experimental.missing_sentinel.MISSING`, declared as
  `Field | MISSING = MISSING  # type: ignore[valid-type]`, with a module-level
  `_is_missing(value: object) -> bool` helper. Stage 4 follows this pattern and
  never uses `None` to mean "absent".
- Ordered collections are `tuple[..., ...]` with explicit `Field(min_length=,
  max_length=)` bounds. Collections whose order carries no economic meaning are
  validated unique and sorted.
- `json_schema_extra` callables add `uniqueItems`, `dependentRequired`, and
  `oneOf` constraints that Pydantic does not emit.

### 3.2 Identifiers (`crypto_lab.domain.identifiers`)

- `exact_string_schema(runtime_pattern, *, min_length=None, max_length=None)`
  converts a `$`-terminated runtime pattern into an ECMA-safe
  `(?![\s\S])`-terminated JSON Schema pattern. Every new constrained string
  type in Stage 4 uses it.
- `validate_prefixed_uuid4(value, prefix)`.
- Existing types: `ExperimentId` (`exp_`), `RunId` (`run_`), `ArtifactId`
  (`art_`), `DatasetId` (`ds_`), `StrategyId` (`strat_`), `StrategyVersionId`
  (`strv_`), `InvocationId` (`inv_`), `EventId` (`evt_`),
  `CandidateArtifactId` (`cand_`), `DiagnosticId` (`diag_`), `AuditEventId`
  (`audit_`), `DatasetPartitionId` (`part_`), `Sha256`,
  `NormalizedIdentifier` (`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`, 1–128),
  `AssetCode`.
- `StrategyId` and `StrategyVersionId` already exist. Stage 4 **does** add two
  new prefixed identifier types to `crypto_lab/domain/identifiers.py`, which
  specification section 10.1 permits as an open list:
  `ApproximationId` with prefix `appx_` for
  `ApproximationDeclaration.approximation_id`, and
  `AvailabilityObservationId` with prefix `avail_` for
  `RuntimeAvailabilityObservation.availability_observation_id`. Both follow the
  existing `validate_prefixed_uuid4` plus `exact_string_schema` pattern
  verbatim. This adds lines to `identifiers.py`, recorded in section 6.2.

### 3.3 Financial and time primitives

- `crypto_lab.domain.financial` — `CanonicalDecimal`, `PositiveDecimal`,
  `NonNegativeDecimal`; `format_decimal`, `parse_decimal`,
  `MAX_DECIMAL_TEXT_LENGTH = 256`; negative zero and non-finite forbidden;
  Python mode requires a real `Decimal`, JSON mode requires a canonical string.
- `crypto_lab.domain.time` — `UtcDateTime`, `require_utc`, `format_utc`,
  `parse_utc`; naive and non-UTC offsets rejected; RFC 3339 with `Z`.

### 3.4 Canonical JSON and hashing

- `crypto_lab.domain.canonical_json.canonical_json_text` /
  `canonical_json_bytes` — sorted keys, compact separators,
  `ensure_ascii=False`, `allow_nan=False`, UTF-8 without BOM; floats rejected;
  `Decimal` via `format_decimal`; `datetime` via `format_utc`; `StrEnum` via
  `.value`; cycles rejected.
- `crypto_lab.domain.hashing` — `HashingProfile` (`StrEnum`) currently
  `CONFIGURATION_AUDIT_V1`, `CONFIGURATION_MATERIAL_BASE_V1`,
  `DATASET_METADATA_V1`, `ARTIFACT_OWNER_V1`; `CanonicalHashEnvelope`
  (`schema_version`, `hashing_profile`, `payload`); `sha256_bytes`;
  `profile_hash(profile, payload)`; `attempt_token_hash`.
- Stage 4 adds exactly two members: `DIAGNOSTIC_IDENTITY_V1 = "diagnostic-identity/v1"`
  in Task 2 and `STRATEGY_VERSION_V1 = "strategy-version/v1"` in Task 5. Both
  hash through `profile_hash`. Stage 4 defines no ad-hoc digest.

### 3.5 Diagnostics (`crypto_lab.domain.diagnostics`)

- `Diagnostic`, `DiagnosticSeverity`, `DiagnosticCategory` (includes
  `USER_CONFIGURATION`, `SCHEMA_VALIDATION`, `COMPATIBILITY`, `SECURITY`),
  `ErrorCode` (`^[A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)+$`, 3–128),
  `BoundedMessage` (1–1024), `DiagnosticDetailValue` bounded JSON union,
  `MAX_DETAIL_*` ceilings, secret-like detail-key rejection.
- Stage 4 emits only `Diagnostic` values with `ErrorCode` values from the
  closed table in section 5.9. It adds no `DiagnosticCategory` member.

### 3.6 Versioning, descriptors, ownership, configuration, datasets

- `crypto_lab.domain.versioning` — `SemanticVersion`,
  `parse_semantic_version`, `SEMANTIC_VERSION_PATTERN`.
- `crypto_lab.adapters.descriptors` — `EngineDescriptor`, `AdapterDescriptor`,
  `SupportedSchemaVersion`, `OperatingSystem`, `BoundedText` (1–1024),
  `CapabilityName` (`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$`, 3–128),
  `VocabularyVersion` (`^capabilities/v[1-9][0-9]*$`, max 32), plus
  `_unique_sorted_text`, `_unique_sorted_versions`, `_set_unique_items`.
  `AdapterDescriptor` already validates that native, approximated, and
  unsupported capability sets are pairwise disjoint.
- `crypto_lab.adapters.versioning.highest_common_stable_version`.
- `crypto_lab.artifacts.ownership` — six owner variants,
  `ArtifactOwnerRef` discriminated union, `ARTIFACT_OWNER_ADAPTER`,
  `owner_presentation`, `artifact_owner_hash`. `StrategyArtifactOwner` requires
  exactly one of `strategy_version_id` or `strategy_version_hash`. Stage 4
  changes none of it.
- `crypto_lab.configuration` — `models.py`, `loader.py`, `snapshot.py`.
  Sources are compiled defaults, one explicitly named primary TOML file, one
  optional explicitly named override file, and allowlisted typed CLI overrides.
  No environment layer, no discovery, no implicit file. Stage 4 adds no
  configuration key.
- `crypto_lab.datasets` — `models.py`, `hashing.py`. Stage 4 does not touch
  dataset contracts.

### 3.7 Schema registry and generation

- `crypto_lab.schema_registry` — frozen slotted `SchemaDefinition(relative_path:
  PurePosixPath, schema_id: str, adapter: TypeAdapter[Any])`;
  `SCHEMA_DEFINITIONS` tuple of 11; `JSON_SCHEMA_DRAFT =
  "https://json-schema.org/draft/2020-12/schema"`;
  `render_schema_files()` renders `adapter.json_schema(mode="serialization")`,
  sets `$schema` and `$id`, and emits `canonical_json_bytes(schema) + b"\n"`,
  after asserting path and identifier uniqueness.
- `scripts/generate_schemas.py` — `--output` plus mutually exclusive `--check`
  or `--write`; registry-driven; creates parent directories; rejects symlinked
  roots or entries and unexpected files. **No generator change is required for
  new schemas**; adding registry entries is sufficient.
- `scripts/verify_schema_distribution.py` — byte-compares reviewed source
  schemas against the single wheel copy under `crypto_lab/schemas/` and the
  single sdist copy under `schemas/`.
- `pyproject.toml` `[tool.hatch.build.targets.wheel.force-include]` maps
  `"schemas" = "crypto_lab/schemas"`, so new schema subdirectories are
  distributed without a build change.

### 3.8 Launcher and verifier

- `scripts/invoke-uv.ps1`, as corrected at
  `350fac49ff5b1db4ec62b60c7ade76580f9894dd`, dispatches **five uv bootstrap
  profiles without resolving the project interpreter**:
  `lock-resolve-offline`, `lock-check`, `sync`, `lock-acquire`, and
  `sync-acquire`. Those five do not require `.venv`, and they pass no
  `--python` argument, because uv rejects a `--python` path that does not
  exist with `error: No interpreter found at path`. They select the
  uv-managed CPython 3.12 through `--managed-python`, `--no-python-downloads`,
  and the project `requires-python = ">=3.12,<3.13"`. Every profile passes
  `--no-config`, so uv ignores `.python-version` and `[tool.uv]`; the
  equivalent controls are supplied as explicit flags instead.
- **Every other profile still requires the project interpreter.** The
  remaining fifteen share one dispatch branch that resolves and validates
  `.venv\Scripts\python.exe` and fails closed when it is absent.
- **`sync` is the supported fresh-worktree environment bootstrap.** A new
  worktree runs the launcher `sync` profile first; no direct `uv` command is
  needed, and none is authorized.
- The launcher validates the repository root, and the existing prefix of
  `.venv` → `Scripts` → `python.exe`, for reparse points on **every**
  operation, before dispatch.
- Closed profiles, unchanged at twenty: `lock-check`, `lock-resolve-offline`,
  `sync`, `lock-acquire`, `sync-acquire`, `ruff-format-all`, `ruff-check-all`,
  `mypy-all`, `pytest-all`, `pytest-launcher-bootstrap`, `pytest-focused`,
  `schema-generate-write`, `schema-generate-check`, `schema-distribution`,
  `cli-version`, `cli-module-version`, `cli-help`, `cli-unknown`,
  `pydantic-proof`, `build`.
- `pytest-focused` accepts only repository-relative targets matching
  `^tests/[A-Za-z0-9_./-]+(?:::[A-Za-z0-9_]+)?$`, an optional leading
  `-o addopts=`, and a final `-q`. Targets may not contain spaces.
- `scripts/verify.ps1` runs, in order: `lock-check`, `sync`,
  `ruff-format-all`, `ruff-check-all`, `mypy-all`, `schema-generate-check`,
  `pytest-all`, `build`, `schema-distribution`, `git diff --check`.

### 3.9 Closed-world guards Stage 4 must update

`tests/safety/test_stage3_boundaries.py` is a closed-world guard. Stage 4
cannot add a single source file, import root, or schema without editing it.

| Guard | Current value | Stage 4 obligation |
|---|---|---|
| `_ALLOWED_SOURCE_FILES` | 33 exact relative paths | Add all 18 new `strategy/*.py`, `capabilities/*.py`, and `domain/*.py` files listed in Appendix C, each in the task that creates it, taking the set to 51 |
| `_ALLOWED_IMPORT_ROOTS` | 17 roots | Add `codecs`, `contextlib`, `copy`, and `yaml`, taking the set to 21. The bytes-only contract of section 5.2 removes any need for `io`; `re` is already present |
| `_DEFERRED_DEFINITIONS` | 79 names | Remove exactly the names Stage 4 defines (section 9.8) |
| `test_schema_registry_is_closed_and_protocol_descriptors_are_located_correctly` | `assert len(paths) == 11` | Change to `20` |
| `test_stage3_completion_status_is_exact` | Pins far more than the Stage 3 row: the roadmap status line `Stages 1 through 3 complete`; the sentence `Stages 1 through 3 have approved detailed implementation plans.`; the Stage 3 approved-plan line; the Stage 3 dependency-bootstrap control row; three negative assertions, one of which pins the absence of `Complete at` plus the Stage 3 Task 8 hash; the Stage 4 phrase `Eligible for just-in-time planning after Stage 3 completion`; the literal `` `DISABLED_WITH_EVIDENCE` ``; and the README line `**Status:** Project 1 Stages 1-3 complete` | See the status-authority rule below. No task may weaken a Stage 3 assertion |
| Stage 4 plan-approval status guard | Added by the **separate roadmap-and-guard commit** that follows this plan's approval commit — not by the plan commit itself, which cannot pin its own hash. It pins the corrected-plan approval commit and the launcher bootstrap prerequisite, and asserts Stage 4 implementation is not started | Task 9 replaces the not-started assertions with completion assertions; no other task touches it |

**Status-authority rule.** Stage 4 completion necessarily invalidates four
strings that `test_stage3_completion_status_is_exact` pins, so a blanket "no
Stage 4 task touches this test" is unsatisfiable. Authority is therefore split
narrowly and exhaustively:

- **Task 8** may update exactly the README status-line assertion, in the same
  commit that updates `README.md`. Nothing else.
- **Task 9** may update exactly the roadmap status line, the
  `Stages 1 through 3 have approved detailed implementation plans.` sentence,
  and the `Eligible for just-in-time planning after Stage 3 completion` phrase,
  each replaced by an equally exact Stage 4 assertion. Nothing else.
- **No task** may weaken, delete, or relax any Stage 3 assertion: the Stage 3
  row, its approved-plan line, its dependency-bootstrap control row, all three
  negative assertions, and the `DISABLED_WITH_EVIDENCE` literal all remain
  verbatim. The third negative assertion pins the absence of ``Complete at
  `d5074454…` ``; Task 9 writes a different hash and the phrase
  "Implementation complete at", so it survives untouched.
- Every replacement stays an exact verbatim substring pin. Loosening an
  assertion to a regex or a substring-of-substring is prohibited.
- **The separate roadmap-and-guard commit** that precedes Stage 4 is bound by
  the same rule. It records the corrected plan as approved in the Stage 4 row
  and adds the plan-approval guard; it does not touch any Stage 3 assertion and
  does not pre-empt Task 8's or Task 9's allocations. Note that from that commit
  until Task 9, the roadmap sentence `Stages 1 through 3 have approved detailed
  implementation plans.` understates reality, because Stage 4's plan is
  approved too. That is deliberate: the sentence is reserved to Task 9, and
  restating it earlier would leave two commits competing for one assertion. The
  Stage 4 row carries the precise status in the meantime.

`tests/safety/test_project_dependencies.py` pins
`_EXPECTED_RUNTIME_REQUIREMENTS = ("pydantic>=2.12,<3",)`,
`_EXPECTED_DEVELOPMENT_NAMES` (7 names), and, in
`test_mypy_untyped_import_override_is_exact`, the exact mypy override list.
Task 1 updates the first two and must leave the mypy override list unchanged.

`tests/safety/test_uv_launcher.py` pins the launcher's exact normalized
SHA-256, its closed command set, and its purged-environment-name tuple. Stage 4
adds no launcher profile, so this file changes only if Task 1 proves a change
is unavoidable; the default is no change.

## 4. Selected YAML dependency and research record

### 4.1 Decision

| Field | Value |
|---|---|
| Selected package | **PyYAML** |
| Runtime requirement | `pyyaml>=6.0.3,<7` |
| Development requirement | `types-pyyaml>=6.0.12,<7` |
| Import root | `yaml` |
| Research date | 2026-08-15 |
| Exact release examined | PyYAML 6.0.3 (uploaded 2025-09-25 to 2025-09-29) |
| Stub release examined | types-PyYAML 6.0.12.20260815 |

The choice is fixed. No alternative remains open.

### 4.2 Candidate comparison against the Stage 4 contract

| Criterion | PyYAML 6.0.3 | ruamel.yaml 0.19.1 |
|---|---|---|
| License | MIT | MIT |
| `requires_python` | `>=3.8` | `>=3.9` |
| Python 3.12 classifier | Yes | Yes |
| Windows distribution | `pyyaml-6.0.3-cp312-cp312-win_amd64.whl` plus sdist; no pure-Python wheel | `ruamel_yaml-0.19.1-py3-none-any.whl` (pure Python) plus sdist |
| Development status | 5 — Production/Stable | 4 — Beta |
| Canonical source | `https://github.com/yaml/pyyaml` (Git, public issue tracker, GitHub Advisory Database coverage) | SourceForge Mercurial at `https://sourceforge.net/p/ruamel-yaml/code/` |
| Typing | No `py.typed`; typeshed stubs `types-PyYAML` target `PyYAML==6.0.*` | `Typing :: Typed` classifier; inline annotations |
| Documented safe loader | `yaml.safe_load` / `yaml.SafeLoader` "recognizes only standard YAML tags and cannot construct an arbitrary Python object" | `YAML(typ='safe')` "loading of a document without resolving unknown tags" |
| Documented pre-construction stream API | `yaml.parse` documented to produce "a sequence of parsing events"; `yaml.compose` documented to return "the representation graph"; `yaml.scan` documented; Event and Node classes documented | API page states "Initially only the typical operations are supported"; no documented public event or token API on the `YAML` instance |
| Duplicate keys | Not rejected; last value wins. Project-owned rejection required | Rejected by default; duplicate merge keys never allowed |
| Nesting depth control | None public; project-owned required | `yaml.max_depth` documented |
| Alias / node / size bounds | None public; project-owned required | None public; docs place size and line bounding on the caller |

### 4.3 Why PyYAML

The prompt-level contract requires bounded source bytes, scalar lengths,
collection sizes, nesting depth, node or token count, aliases, and alias
expansion, and it forbids relying on undocumented private internals as the
primary safety contract. Neither candidate bounds all of those publicly, so a
project-owned pre-construction scan is mandatory either way.

The deciding criterion is therefore **which library documents, as public API,
the primitive that the project-owned scan must be built on**. PyYAML documents
`yaml.parse` as producing a parsing-event sequence and `yaml.compose` as
returning a node graph, with documented `Event` and `Node` classes.
ruamel.yaml's own API documentation declines to commit to an equivalent public
stream surface. Building Stage 4's safety boundary on PyYAML's documented event
stream therefore satisfies "no undocumented private internals" directly, while
the equivalent ruamel.yaml construction would rest on a surface its maintainer
has not documented as stable.

Secondary reasons, in order:

1. **Contract stability.** Strategy identity is a permanent content hash. The
   PyYAML 6.0.x public surface has been stable for years; ruamel.yaml remains a
   0.x Beta whose 0.18-to-0.19 transition changed loading API behaviour.
2. **Auditability.** PyYAML's canonical repository is public Git with issue
   history and GitHub Advisory Database coverage, which the reviewed
   supply-chain record in `tools/gitnexus/supply-chain.json` style can cite.
3. **Strict typing without weakening.** typeshed `types-PyYAML` gives complete
   annotations for `parse`, `compose`, `SafeLoader`, events, and nodes, so no
   `ignore_missing_imports` override is added and
   `test_mypy_untyped_import_override_is_exact` stays unchanged. This is the
   normal typed path, not a relaxation.

ruamel.yaml's native duplicate-key rejection and documented `yaml.max_depth`
are real advantages, and the failure modes are **not** symmetric. PyYAML's
`SafeConstructor.construct_mapping` collapses duplicate keys silently,
last-wins; ruamel raises. Under a permanent `content_hash`, a missing or buggy
duplicate-key check in PyYAML therefore produces a strategy that silently means
something other than its source text, with no error anywhere, whereas the same
bug under ruamel fails loudly. That asymmetry does not flip the decision,
because the documented-stream-API criterion above is decisive and because
`yaml.max_depth` is a parser option rather than a streaming surface, but it
does oblige a named compensating control: duplicate keys are rejected inside
the single pre-construction pass of section 5.2 item 9, and no code path
produces a mapping without that check having run. A test builds a duplicated
key directly and asserts `STRATEGY.YAML_DUPLICATE_KEY`.

Section 4.2 also records that PyYAML ships no pure-Python wheel. Every safety
argument in this plan reasons about the **pure-Python** implementation — the
non-recursive Scanner and Parser, `Event` semantics, and copy-on-write
constructor registration. Importing `yaml` nevertheless loads the optional
compiled extension on the selected Windows wheel; Appendix J records that
evidence and the exact consequences. The compensating control is that Task 1
forbids the libyaml surface by name and pins `yaml.SafeLoader` in the loader's
MRO, so a future change cannot silently route through `CSafeLoader` and
invalidate that reasoning.

### 4.4 Official security record

| Advisory | CVE | Affected surface |
|---|---|---|
| GHSA-rprw-h62v-c2w7 | CVE-2017-18342 | `yaml.load` with the default unsafe loader |
| GHSA-3pqx-4fqf-j49f | CVE-2019-20477 | Unsafe deserialization path |
| GHSA-6757-jp84-gxfx | CVE-2020-1747 | `FullLoader` input validation |
| GHSA-8q59-q68h-6hv4 | CVE-2020-14343 | `FullLoader` input validation |

Every published PyYAML advisory concerns the non-safe loaders (`yaml.load`
with the default loader, or `FullLoader`), and every one is remediated in a
release below the selected floor of 6.0.3. None concerns `SafeLoader` or
`safe_load`. Stage 4 never calls `yaml.load`, `yaml.full_load`,
`yaml.unsafe_load`, `FullLoader`, `UnsafeLoader`, or `Loader`; Task 1 adds a
source-level guard test that forbids those exact names.

The residual documented risks that Stage 4 must own itself are entity or alias
expansion, unbounded nesting, unbounded document size, duplicate keys, multiple
documents, and the documented ability to register safe constructors globally by
subclassing `yaml.YAMLObject` with `yaml_loader = yaml.SafeLoader`. Section 5
defines the controls.

### 4.5 Recorded research facts

- Research date: 2026-08-15. Sources: PyPI JSON metadata for `PyYAML`,
  `PyYAML/6.0.3`, `ruamel.yaml`, `ruamel.yaml/0.19.1`, and `types-PyYAML`;
  `https://pyyaml.org/wiki/PyYAMLDocumentation`;
  `https://yaml.dev/doc/ruamel.yaml/` including `/basicuse/` and `/cve/`;
  the GitHub Advisory Database index for PyYAML.
- Research was read-only. No package was installed, downloaded, or executed as
  part of selection. Research does not authorize acquisition; section 8
  governs acquisition.
- The generated `uv.lock` supplies the exact installed version and per-artifact
  SHA-256 during implementation. This planning task changes neither
  `pyproject.toml` nor `uv.lock`.

## 5. Global security and determinism constraints

### 5.1 Prohibited behaviour

Stage 4 code must never perform, and Task 1 adds source-level tests that
forbid: arbitrary Python execution; `eval`; `exec`; `compile`; dynamic imports
(`importlib`, `__import__`); custom YAML object construction; extension
execution; engine imports; filesystem access from expressions, evaluation, or
resolution; network access; environment-variable access; subprocess execution;
order simulation; fill simulation; portfolio accounting; real backtests;
optimization; strategy promotion; persistence; databases; live trading; paper
trading.

`crypto_lab.strategy` and `crypto_lab.capabilities` must not import `os`,
`pathlib`, `socket`, `subprocess`, `importlib`, `random`, `time`, or
`datetime.datetime.now`. Deterministic timestamps enter only as explicit
`observed_at_utc` parameters supplied by the caller.

### 5.2 Safe YAML loading contract

`crypto_lab.strategy.yaml_source` is the only module permitted to import
`yaml`, and Task 1 adds an executable test that proves it (section 9, Task 1,
step 3). Its single public entry point is **bytes-only** and never accepts a
path, a file object, or any stream:

```text
load_yaml_document(
    source: bytes,
    source_name: SourceName,
    observed_at_utc: datetime,
) -> Result[YamlDocument]
```

It must, in this exact order. **Step 0 comes before everything else:**

0. **Validate `source_name` at the entry point.** `SourceName` is an
   `Annotated` alias, and Python performs no runtime validation on a plain
   function parameter, so the type alone guarantees nothing about a real
   caller. Validate it with a module-level
   `TypeAdapter(SourceName).validate_python(source_name)` before touching
   `source`, converting failure to a `Result` failure carrying
   `STRATEGY.SOURCE_NAME_INVALID`. **That diagnostic must not echo the
   offending value**, for the same reason step 0 exists: a rejected
   `source_name` is exactly the path or username the step is guarding against.
   It carries the fixed project-authored message for its code and no detail
   derived from the input, and a test asserts the rejected value's distinctive
   substrings are absent from the emitted diagnostic. Item 14 below bans
   `Mark.name`, but a
   caller-supplied `source_name` is the wider redaction channel: it flows into
   diagnostics and into `StrategySourceProvenance`, and specification section
   24.3 forbids a local path or username reaching either. Without step 0 the
   first validation would be `StrategySourceProvenance` construction in Task 5,
   on the success path only.
1. Accept only `bytes`. Reject `str`, `pathlib.Path`, `io.StringIO`,
   `io.BytesIO`, and every object exposing `read`, `name`, or `fileno`. A
   stream branch is prohibited: PyYAML's `Reader.determine_encoding()` performs
   its own BOM sniffing and would accept UTF-16 through a contract that
   declares strict UTF-8, and a real file object's `.name` would propagate a
   filesystem path into `Mark.name` and from there into diagnostics.
2. Reject `len(source) > MAX_SOURCE_BYTES` (`262_144`).
3. Reject any leading `codecs.BOM_UTF8`, `BOM_UTF16_LE`, `BOM_UTF16_BE`,
   `BOM_UTF32_LE`, or `BOM_UTF32_BE`.
4. Decode exactly once with `source.decode("utf-8")` (strict), converting
   `UnicodeDecodeError` to `STRATEGY.SOURCE_NOT_UTF8`.
5. Pass the resulting immutable `str` to a **single** `yaml.parse(text,
   Loader=StrictStrategySafeLoader)` pass. PyYAML's `Reader` accepts `str`
   natively and performs no encoding detection on it.
6. Build the bounded plain value **directly from that one event stream** using
   a project-owned event-to-value builder. `yaml.compose`, `yaml.compose_all`,
   `yaml.load`, `yaml.safe_load`, and the Constructor are never called. There
   is exactly one pass over the source, so no rewind is required and no
   scan-versus-compose divergence is possible. Aliases are expanded by the
   builder itself under the accounting of section 5.3, so no shared node graph
   and no cyclic graph can ever exist.
7. Classify every event with the **project-owned event classifier** of section
   5.2.1. That classifier, not `event.tag`, decides the type of every
   implicitly typed scalar, because a `yaml.parse` event carries **no resolved
   implicit tag**. An earlier draft of this plan said the pass could "accept
   only the resolved tags"; that was wrong, and section 5.2.1 records the
   PyYAML 6.0.3 evidence that disproves it.
8. Apply the mapping-key contract of section 5.2.2 to every event in key
   position. Floats, timestamps, nulls, YAML 1.1 boolean aliases, alternate
   integer notations, merge forms, and empty plain scalars are all rejected, so
   authoritative numeric values reach Pydantic only as canonical decimal
   strings or integers, and no value the author never wrote can enter a
   permanent `content_hash`. `canonical_json_bytes` rejects floats as a second
   independent net.
9. Reject duplicate mapping keys deterministically **before** any mapping value
   is materialised, comparing the **classified key strings** of section 5.2.2
   and reporting the first duplicate in document order with its key and its
   line and column. There is no code path that produces a `dict` without this
   check having run. PyYAML's own behaviour is silent last-wins, so this control
   is the only thing standing between a duplicated key and a silently wrong
   permanent hash.
10. Reject the `<<` merge key unconditionally in `strategy/v1` **in key
    position**, whether it arrives as the classified string `<<`, as the quoted
    `"<<"`, or as an explicit `tag:yaml.org,2002:merge`, under the precedence
    order of section 5.2.2. Merge semantics would make canonical content depend
    on resolution order and are unnecessary for version 1. Also reject any
    `DocumentStartEvent` carrying a `%YAML` or `%TAG` directive — assert
    `event.version is None and not event.tags` — with
    `STRATEGY.YAML_DIRECTIVE_FORBIDDEN`. PyYAML accepts a `%YAML 1.2` header
    while its resolver remains YAML 1.1, and `%TAG` remaps shorthand prefixes;
    neither may silently redefine the semantics this section fixes.
11. Leave global parser state untouched. `StrictStrategySafeLoader` is a
    private subclass of `yaml.SafeLoader` whose **class body is empty** except
    for its name, because the Constructor is never invoked and therefore no
    constructor is required. The module must never call `add_constructor`,
    `add_multi_constructor`, or `add_implicit_resolver`, must never assign into
    `yaml_constructors`, `yaml_multi_constructors`, or
    `yaml_implicit_resolvers`, and must never register a `yaml.YAMLObject`.
    Note that an unqualified `StrictStrategySafeLoader.yaml_constructors[t] = f`
    mutates the **inherited** `yaml.SafeLoader` dict, because the subclass does
    not own that attribute until PyYAML's copy-on-write `add_constructor` runs;
    section 9 Task 1 bans those attribute names outright.
12. Guarantee fresh parser state after failure. Each call constructs a new
    loader; no loader, parser, scanner, or reader is cached, reused, or stored
    at module scope. The `yaml.parse` generator is closed explicitly with
    `contextlib.closing` on every early return so `Loader.dispose()` runs
    deterministically rather than at garbage collection. A test parses an
    invalid document and then a valid document in the same process and asserts
    a result identical to loading the valid document alone.
13. Hand off to Pydantic in **JSON mode**. `load_yaml_document` itself returns
    `Result[YamlDocument]` and imports no model; the handoff is performed by the
    **caller** — `StrategyLoader` in production, and the test body in Task 2
    step 14. The bounded plain value is
    serialised with `crypto_lab.domain.canonical_json.canonical_json_bytes` and
    validated with `StrategySpec.model_validate_json(...)`. This is mandatory,
    not stylistic: `crypto_lab.domain.financial.parse_decimal` branches on
    `info.mode` and, in Python mode, raises `"Python input must be Decimal"`
    for the `str` the builder produces, so `model_validate(mapping)` would make
    every decimal field unloadable. `canonical_json_bytes` also rejects floats,
    giving a second independent net behind item 7.
    **Authoring consequence:** every decimal-valued field must be a quoted
    string in exact `CANONICAL_DECIMAL_PATTERN` form. `"1"` is valid; `"1.50"`,
    `"+1"`, `"1e3"`, and unquoted `1` are not. Every fixture must comply.
14. Never let a `Diagnostic` carry `str(yaml.YAMLError)`, `Mark.get_snippet()`,
    `Mark.buffer`, `Mark.name`, or `MarkedYAMLError.problem`, `.context`, or
    `.note`. The three `MarkedYAMLError` attributes matter independently:
    `problem` embeds document characters verbatim — for example
    `found unknown escape character %r` — so a document byte would reach a
    diagnostic through it. Only the integer `line` and `column` from a `Mark`,
    plus a fixed project-authored message per error code, may enter a
    diagnostic. The Task 1 AST guard bans five of these attribute names —
    `get_snippet`, `buffer`, `problem`, `context`, `note` — statically.
    `Mark.name` is **not** in the static guard, because bare `name` is bound in
    three comprehensions in `crypto_lab/configuration/loader.py` and banning it
    would be un-greenable; with a `str` stream `Mark.name` is the constant
    `"<unicode string>"`, so there is no live leak channel, and `Mark.name`
    remains prohibited at the test level. A test asserts that a syntax-error
    diagnostic contains none of the document's distinctive tokens.

Typing note: typeshed annotates PyYAML node and event `value` attributes as
`Any`. `disallow_any_expr` is not part of mypy `strict`, so the builder must
narrow with `isinstance` rather than assigning through an `Any`.

#### 5.2.1 Project-owned event classifier

**Recorded PyYAML 6.0.3 evidence.** This subsection is the review package for
the event contract; both plan reviewers read it directly, because PyYAML is not
installed during planning and the evidence is therefore documentary.

- `yaml/parser.py` `parse_node` constructs `ScalarEvent(anchor, tag, implicit,
  value, start_mark, end_mark, style=style)`. `tag` is `None` when the node
  carries no tag property. `implicit` is `(True, False)` for a plain untagged
  scalar, `(False, True)` for a quoted or block untagged scalar, and
  `(False, False)` for a scalar carrying a specific tag.
- **The non-specific tag `!` is the one exception, and it is load-bearing.**
  `parse_node` computes `implicit = (tag is None or tag == '!')` and then, for a
  scalar, `if (token.plain and tag is None) or tag == '!': implicit = (True,
  False)`. With `DEFAULT_TAGS = {'!': '!', '!!': 'tag:yaml.org,2002:'}` and
  `Scanner.scan_tag` returning `'!'` for a bare `!`, the node `! abc` yields
  `ScalarEvent(tag='!', implicit=(True, False), style=None)` and `! "yes"`
  yields `ScalarEvent(tag='!', implicit=(True, False), style='"')`.
  `MappingStartEvent` and `SequenceStartEvent` behave the same way, carrying
  `tag='!'` with `implicit=True`. `yaml/composer.py` matches this with the guard
  `if tag is None or tag == '!': tag = self.resolve(...)`.
- `yaml/composer.py` `Composer.compose_scalar_node` is where implicit type
  resolution happens: under that guard it calls `self.resolve(ScalarNode,
  event.value, event.implicit)` against `yaml/resolver.py`. Stage 4 never
  enters the Composer, so **no parse event ever carries a resolved implicit
  tag**. Reading an implicit type from `event.tag` reads `None`.
- `yaml/scanner.py` fixes the style values: `scan_plain` produces
  `ScalarToken(..., plain=True)` with the default `style=None`;
  `scan_flow_scalar` passes `'` or `"`; `scan_block_scalar` passes `|` or `>`.
- `yaml/events.py` defines exactly ten concrete event classes:
  `StreamStartEvent`, `StreamEndEvent`, `DocumentStartEvent`,
  `DocumentEndEvent`, `AliasEvent`, `ScalarEvent`, `SequenceStartEvent`,
  `SequenceEndEvent`, `MappingStartEvent`, `MappingEndEvent`. `AliasEvent`
  derives from `NodeEvent` and carries **neither** `.tag` nor `.implicit`, so
  dispatch must be explicit rather than duck-typed.
- `yaml/resolver.py` registers exactly eight default implicit resolvers:
  `bool`, `float`, `int`, `merge`, `null`, `timestamp`, `value`, and `yaml`.
  The `yaml` resolver is unreachable — PyYAML's own comment records that a
  plain scalar cannot begin with `!`, `&`, or `*` — leaving seven reachable
  families the classifier must account for.

**The "explicit tag" predicate is `event.tag is not None`.** That single
predicate selects between the two scalar rule sets below and between the two
collection rules. The non-specific tag `!` therefore counts as an explicit tag
and is **rejected** with `STRATEGY.YAML_FORBIDDEN_TAG`, on scalars and on
collections alike, because `strategy/v1` accepts no tag it has not named.

**The classifier dispatches on the exact event class, and is total by
construction.** Its roles are fixed:

| Event class | Role |
|---|---|
| `StreamStartEvent`, `StreamEndEvent` | stream framing; consumed, no value |
| `DocumentStartEvent` | first one opens the document; a second is `STRATEGY.YAML_MULTIPLE_DOCUMENTS`; none is `STRATEGY.YAML_EMPTY_DOCUMENT` |
| `DocumentEndEvent` | closes the document; any later value event is `STRATEGY.YAML_MULTIPLE_DOCUMENTS` |
| `ScalarEvent` | classified by the scalar rules below |
| `SequenceStartEvent`, `MappingStartEvent` | classified by the collection rules below |
| `SequenceEndEvent`, `MappingEndEvent` | close the open collection |
| `AliasEvent` | expanded under section 5.3.1; rejected in key position by section 5.2.2 |

Dispatch ends in a **terminal `else` that returns a `Result` failure**, never
an exception and never a silent skip, so an event kind added by a future PyYAML
release fails closed. A test asserts the handled class set equals the concrete
subclasses reachable from `yaml.events.Event`, so such an addition fails loudly
rather than degrading.

The classifier is the only place a YAML type is decided. It never consults
`yaml/resolver.py`, no mutable global implicit resolver is read or written, and
`yaml.compose`, `yaml.compose_all`, `yaml.load`, `yaml.safe_load`, and the
Constructor are never called.

**Collection events**

- `MappingStartEvent` with `event.tag is None` is a map.
- `SequenceStartEvent` with `event.tag is None` is a sequence.
- An explicit collection tag must exactly match the event kind:
  `tag:yaml.org,2002:map` is accepted only on a `MappingStartEvent`, and
  `tag:yaml.org,2002:seq` only on a `SequenceStartEvent`.
- Any other tag on a collection event is rejected with
  `STRATEGY.YAML_FORBIDDEN_TAG`. That includes the non-specific tag `!`, a
  mismatched collection tag, a scalar tag on a collection,
  `tag:yaml.org,2002:omap`, `:set`, `:pairs`, `:binary`, every `!!python/...`
  form, and every unknown custom tag.

**Scalar events with an explicit tag** (`event.tag is not None`)

| Tag | Classification |
|---|---|
| `tag:yaml.org,2002:str` | string, verbatim text |
| `tag:yaml.org,2002:int` | integer, accepted only when the text matches `^(0\|-?[1-9][0-9]*)$` **and** the value is within the section 5.3 integer bounds |
| `tag:yaml.org,2002:bool` | boolean, accepted only for exactly lowercase `true` or `false` |
| `tag:yaml.org,2002:null` | rejected for `strategy/v1` |
| `!` (non-specific) | rejected |
| every other tag | rejected |

A rejected tag yields `STRATEGY.YAML_FORBIDDEN_TAG`. An accepted tag whose text
fails its canonical form yields `STRATEGY.YAML_NONCANONICAL_SCALAR`, and one
whose value falls outside the integer bounds yields
`STRATEGY.YAML_INTEGER_OUT_OF_RANGE`.

`!!str` with empty text classifies as the empty string. This is deliberate and
asymmetric with the plain empty scalar, which rule 5 rejects: an explicit
`!!str` is an unambiguous authored intent, whereas a bare empty plain scalar is
YAML 1.1 null. The asymmetry is hash material, so a test pins both halves.

**Scalar events without an explicit tag** (`event.tag is None`)

1. Quoted, literal, and folded scalars are strings. A scalar is non-plain
   exactly when `event.style` is one of `'`, `"`, `|`, `>`.
2. A plain scalar is one whose `event.style` is `None` or empty. For defence in
   depth the classifier also reads `event.implicit`: a plain style must present
   `implicit[0] is True`, and a non-plain untagged style must present
   `implicit == (False, True)`. A disagreement is **rejected** with
   `STRATEGY.YAML_NONCANONICAL_SCALAR`, never resolved. Note that for untagged
   scalars PyYAML cannot produce a disagreement — `token.plain` determines both
   — so this check is unreachable by any authored document and exists only to
   fail closed if that invariant ever changes. Its test therefore constructs a
   synthetic `yaml.ScalarEvent(...)` directly and feeds it to the classifier;
   it is not authored as YAML.
3. A plain scalar whose text is exactly lowercase `true` or `false` is a
   boolean.
4. A plain scalar whose text matches `^(0|-?[1-9][0-9]*)$` **and** whose value
   lies within the section 5.3 integer bounds is an integer. The pattern
   excludes `-0`, because `int("-0") == 0` would let two source texts produce
   one canonical value, and the repository already forbids negative zero in
   `format_decimal`. A matching text whose value is out of range is rejected
   with `STRATEGY.YAML_INTEGER_OUT_OF_RANGE`; see section 5.3 for why a digit
   cap alone is insufficient.
5. **The rejection rule, stated by construction rather than by example.**
   Rules 3 and 4 are evaluated **first and win**: a text they accept is never
   consulted against this table. That ordering is load-bearing, because
   `^\+[0-9][0-9_]*$` and the underscore pattern deliberately overlap the
   integer shape, and without it an implementation that ran the table first
   would reject every negative integer while still passing every other required
   test. Required test 2 therefore includes plain `-5` and `0` alongside `20`.
   A plain scalar not accepted by rule 3 or rule 4 is rejected with
   `STRATEGY.YAML_NONCANONICAL_SCALAR` when it matches any project-owned
   rejection pattern below. Outside key position these patterns are
   deliberately **at least as broad as** PyYAML's own resolver regexes, with
   exactly one documented exception — the merge token `<<`, which section 5.2.2
   handles more strictly in key position and which is an ordinary string
   elsewhere. Subject to that exception the contract holds even against a
   reader that implements YAML 1.1 more completely than PyYAML does. Every remaining valid plain scalar is a string.

   | Family | Project-owned rejection pattern |
   |---|---|
   | boolean aliases | `^(?:y\|Y\|yes\|Yes\|YES\|n\|N\|no\|No\|NO\|on\|On\|ON\|off\|Off\|OFF\|True\|TRUE\|False\|FALSE)$` |
   | alternate integers | `^[-+]?0b[01_]+$`, `^[-+]?0o?[0-7_]+$`, `^[-+]?0x[0-9a-fA-F_]+$`, `^\+[0-9][0-9_]*$`, `^-?0[0-9_]+$`, `^-0$`, underscore-bearing `^[-+]?[0-9][0-9_]*_[0-9_]*$`, and sexagesimal `^[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+$` |
   | floats | `^[-+]?(?:\.[0-9_]+\|[0-9][0-9_]*\.[0-9_]*)(?:[eE][-+]?[0-9]+)?$`, `^[-+]?[0-9][0-9_]*[eE][-+]?[0-9]+$`, sexagesimal `^[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*$`, and `^[-+]?\.(?:inf\|Inf\|INF)$`, `^\.(?:nan\|NaN\|NAN)$` |
   | timestamps | `^[0-9]{4}-[0-9]{2}-[0-9]{2}$` and `^[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:[Tt]\|[ \t]+)[0-9]{1,2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]*)?(?:[ \t]*(?:Z\|[-+][0-9]{1,2}(?::[0-9]{2})?))?$` |
   | nulls | `^(?:~\|null\|Null\|NULL\|)$` — the empty alternative covers the empty plain scalar, matching PyYAML's own null resolver form |
   | value | `^=$`, the `tag:yaml.org,2002:value` token |

   Every entry is a complete regular expression. No entry is a pattern plus a
   prose condition: the underscore case is `^[-+]?[0-9][0-9_]*_[0-9_]*$`, which
   requires a literal `_`, because the unconditional `^[-+]?[0-9][0-9_]*$`
   would also reject plain `1000` that rule 4 must accept; the boolean row
   simply omits lowercase `true` and `false` rather than subtracting them in
   prose; and `^-0$` is listed explicitly, because rule 4's pattern excludes
   `-0` and every other integer entry requires a further digit, so without it
   `-0` would fall through to the string case and required test 21 would be
   unsatisfiable. `^-0$` is deliberately narrow: widening to
   `^[-+]?0[0-9_]*$` would also match plain `0`, which rule 4 must accept, and
   would put this row back into dependence on precedence prose. The second timestamp
   entry is PyYAML's own second alternative written out — note the `[Tt]` or
   `[ \t]+` separator, single-digit month, day and hour, optional fractional
   seconds, and optional `[ \t]*` before the zone — so required test 13's
   `2026-08-15T00:00:00Z` is matched by a stated pattern rather than by prose.

   The float family covers **sexagesimal floats** such as `190:20:30.15`
   explicitly, which PyYAML resolves to `685230.15`. `1e3` and single-letter
   `y`/`n` are rejected even though PyYAML itself types them as strings; that
   is intentional cross-implementation safety, not a claim about PyYAML.
   Note that the merge token `<<` is **not** in this list: section 5.2.2
   rejects it in key position with `STRATEGY.YAML_MERGE_KEY_FORBIDDEN`, and
   outside key position it is an ordinary string.

   These patterns must not reject a legitimate instrument identifier. Every
   sexagesimal pattern requires digit groups, so `BINANCE:BTC/USDT:SPOT`,
   `bar.close`, `indicator.sma/v1`, and `1h` all remain strings. A test pins
   each of those four explicitly, because an over-broad colon rejection would
   break every fixture in section 6.5.

**Authoring consequence.** Because floats are rejected and `strategy/v1`
declares no nullable field, every decimal-valued field must be a quoted string
in exact `CANONICAL_DECIMAL_PATTERN` form, and an absent value is expressed by
omitting the key rather than by writing a null. `"1"` is valid; `"1.50"`,
`"+1"`, `"1e3"`, and unquoted `1.0` are not.

**Exact required tests.** One test each:

1. an implicit scalar event's `tag` is `None`, asserted directly against a
   `yaml.parse` event, so the contract's premise is executable rather than
   assumed;
2. canonical integers `20`, `-5`, and `0` classify as integers, pinning that
   rules 3 and 4 precede the rejection table;
3. canonical boolean `true` and `false` classify as booleans;
4. a quoted ambiguous string `"yes"` classifies as the string `yes`, and
   `"1"` as the string `1`;
5. an explicit `!!str yes` classifies as the string `yes`, and `!!str` with
   empty text as the empty string;
6. an explicit `!!int 20` classifies as the integer `20`;
7. an invalid explicit `!!int 0x20` is rejected with
   `STRATEGY.YAML_NONCANONICAL_SCALAR`;
8. plain `yes`, `no`, `on`, `off`, `y`, `n`, and their case variants are
   rejected;
9. octal `010` and `0o17`, leading-plus `+1` and `+0`, and underscore-bearing
   `1_000` are rejected. The last three pin the two table rows that
   deliberately overlap the integer shape; without them both rows could be
   deleted with all other tests still green, and `+1`, `+0`, and `1_000` —
   which PyYAML types as `1`, `0`, and `1000` — would fall through to strings;
10. hexadecimal `0x20` is rejected;
11. sexagesimal integer `12:30` **and sexagesimal float `190:20:30.15`** are
    rejected;
12. floats `1.0`, `.5`, `1.`, `1e3`, `.inf`, `+.INF`, `.nan` are rejected;
13. timestamps `2026-08-15` and `2026-08-15T00:00:00Z` are rejected;
14. nulls `~`, `null`, `Null`, `NULL` are rejected;
15. the empty plain scalar is rejected;
16. an unknown explicit tag `!!binary` and a custom `!Thing` are rejected with
    `STRATEGY.YAML_FORBIDDEN_TAG`;
17. a mismatched collection tag — `!!seq` on a mapping and `!!map` on a
    sequence — is rejected with `STRATEGY.YAML_FORBIDDEN_TAG`;
18. a style/`implicit` disagreement, constructed as a synthetic
    `yaml.ScalarEvent`, is rejected rather than resolved;
19. **the non-specific tag `!`**: `! abc`, `! "yes"`, and `! {a: 1}` are each
    rejected with `STRATEGY.YAML_FORBIDDEN_TAG`, proving the explicit-tag
    predicate is `event.tag is not None` and not `implicit[0] is False`;
20. **the value token** `=` is rejected;
21. **integer bounds and negative zero**: `9223372036854775807` is accepted;
    `9223372036854775808` and a 4301-digit literal are rejected with
    `STRATEGY.YAML_INTEGER_OUT_OF_RANGE`; and `-0` is rejected with
    `STRATEGY.YAML_NONCANONICAL_SCALAR`, **not** the bounds code — it fails
    rule 4's canonical pattern and is caught by the rejection table, so
    asserting the code matters here;
22. **event-kind exhaustiveness**: the classifier's handled class set equals the
    **leaf** classes reachable from `yaml.events.Event` — those with
    `not cls.__subclasses__()` — which is the ten concrete classes, not the
    thirteen a naive recursive walk returns, since `NodeEvent`,
    `CollectionStartEvent`, and `CollectionEndEvent` are intermediate. An
    unhandled kind returns a `Result` failure rather than raising;
23. **identifiers survive**: `BINANCE:BTC/USDT:SPOT`, `bar.close`,
    `indicator.sma/v1`, and `1h` all classify as strings;
24. **directives are rejected**: a document carrying `%YAML 1.2` or a `%TAG`
    directive is rejected with `STRATEGY.YAML_DIRECTIVE_FORBIDDEN`, asserted
    through `DocumentStartEvent.version` and `.tags`.

#### 5.2.2 Mapping-key contract

Inside a mapping, the event in key position obeys this exact contract:

- **Every mapping key is a direct scalar.** The key event must be a
  `ScalarEvent`.
- **It must classify as a string** under section 5.2.1.
- **Aliases are not permitted as mapping keys.** An `AliasEvent` in key
  position is rejected even when its anchor resolves to a string.
- **Sequence and mapping keys are rejected.** A `SequenceStartEvent` or
  `MappingStartEvent` in key position — a complex key — is rejected.
- **Integer, boolean, and null keys are rejected**, whether implicitly typed or
  explicitly tagged.
- **Duplicate detection operates on the classified string.** Quoted and
  unquoted keys with equal text are duplicates, so `a: 1` followed by
  `"a": 2` is a duplicate.

**Error-code assignment, in this exact precedence order**, so no two rules can
claim the same document:

0. A key event that is not a `ScalarEvent` — an `AliasEvent`,
   `SequenceStartEvent`, or `MappingStartEvent` — yields
   `STRATEGY.YAML_MAPPING_KEY_INVALID` immediately. This step runs **first**
   because `AliasEvent` carries no `.tag` attribute at all, so evaluating the
   tag rule below against one would raise `AttributeError` out of the `Result`
   contract. A key scalar longer than `MAX_SCALAR_CHARACTERS` is rejected here
   too, with `STRATEGY.YAML_SCALAR_TOO_LONG`, since the length bound applies to
   every scalar and precedes classification.
1. A key whose event carries a rejected tag — including the non-specific `!`
   and `tag:yaml.org,2002:merge` — yields `STRATEGY.YAML_FORBIDDEN_TAG` from
   section 5.2.1.
2. A key that **classifies as the string `<<`** yields
   `STRATEGY.YAML_MERGE_KEY_FORBIDDEN`. The check is on the classified string,
   so quoted `"<<": x` is rejected exactly like plain `<<: x`. Section 5.2.1
   deliberately does **not** list `<<` among its rejected plain scalars: outside
   key position `<<` is an ordinary string, and putting it in both places would
   make the two rule sets claim the same document with different codes.
3. A key that section 5.2.1 itself rejects keeps **that** section's code, so
   the two rule sets never claim one document: `=` in key position is already
   rejected by 5.2.1's value row with `STRATEGY.YAML_NONCANONICAL_SCALAR`,
   exactly as it would be in value position. Only a key that classifies
   successfully and is then unacceptable **as a key** — an integer, boolean, or
   null classification — yields the new
   `STRATEGY.YAML_MAPPING_KEY_INVALID`. `<<` is the single deliberate
   exception, carved out in step 2, because 5.2.1 does not reject it at all.
4. A duplicate yields the existing `STRATEGY.YAML_DUPLICATE_KEY`, reported for
   the **first** duplicate in document order, with the integer line and column
   of its second occurrence.

**Exact required tests**, one per rejected shape: an alias key; a sequence key
`? [a, b]`; a mapping key `? {a: b}`; an implicit integer key `1:`; an implicit
boolean key `true:`; an implicit null key `~:`; the empty key `:`; an explicit
`!!int 1:` key; an explicit `!!bool true:` key; an explicit `!!null ~:` key; an
unknown-tag key; a non-specific `! k:` key; a `=` key; the merge key `<<:`; the
quoted merge key `"<<":`; a key longer than `MAX_SCALAR_CHARACTERS`; the
quoted-versus-unquoted duplicate pair; and a **three-duplicate ordering test**
asserting that a document with two distinct duplicated keys reports the first in
document order, with the exact line and column of the second occurrence, so a
last-wins or unordered implementation cannot pass.

#### 5.2.3 `SourceName`

`SourceName` is a bounded non-path label, never a filesystem path. It matters
because `StrategySourceProvenance` retains `source_name` for audit, and
specification section 24.3 requires diagnostics and audit details to be
redacted; a raw path would leak a local username.

Its runtime pattern is exactly:

```text
^(?!.*\.\.)[a-z0-9][a-z0-9._-]{0,127}$
```

The existing length bound is kept: 1 to 128 characters.

**Declaration mechanism, and why the pattern is not in
`StringConstraints`.** Pydantic v2 compiles a `StringConstraints` pattern with
its default `rust-regex` engine, which has no look-around. The observed failure
under Pydantic 2.13.4 is exact:

```text
SchemaError: regex parse error:
    ^(?!.*\.\.)[a-z0-9][a-z0-9._-]{0,127}$
     ^^^
error: look-around, including look-ahead and look-behind, is not supported
```

`SourceName` is therefore declared in `src/crypto_lab/strategy/yaml_source.py`
as:

- `StringConstraints(strict=True, min_length=1, max_length=128)` — no
  `pattern`;
- an `AfterValidator` that rejects a value when a module-level
  `re.compile(...)` of the pattern above returns `None` from `fullmatch`;
  `fullmatch` rather than `match`, because Python's `$` also matches before a
  trailing newline;
- `WithJsonSchema(exact_string_schema(...))`, which converts the
  `$`-terminated runtime pattern into the ECMA-safe
  `(?![\s\S])`-terminated JSON Schema form. Negative look-ahead is valid
  ECMA-262, so the generated schema keeps the full constraint, and the existing
  `test_every_schema_pattern_uses_absolute_end_semantics` guard still passes.

Do not move the pattern into `StringConstraints(pattern=...)`; it will not
build. `re` is already in `_ALLOWED_IMPORT_ROOTS`.

**Exact required tests.** Reject `strategy..yaml`; `.hidden`; path separators
`a/b.yaml` and `a\b.yaml`; drive syntax `c:\x\y.yaml` and `C:\x\y.yaml`; UNC
syntax `\\host\share\x.yaml` and `//host/share/x.yaml`; a leading tilde
`~x.yaml` and `~/x.yaml`; uppercase `Strategy.yaml`; a leading `-`; and an
embedded space. Accept `strategy.yaml`, `sma_cross_long.valid.yaml`, and a
128-character name; reject a 129-character name.

Two further tests are mandatory, because the type alias alone enforces nothing:

- **`load_yaml_document` itself rejects a bad name.** Call the entry point with
  `C:\x\y.yaml` and with `strategy..yaml` and assert a `Result` failure
  carrying `STRATEGY.SOURCE_NAME_INVALID`, per section 5.2 step 0. A test that
  only exercises `TypeAdapter(SourceName)` would pass while the entry point
  accepted anything.
- **The generated JSON Schema agrees with the runtime pattern.** Validate the
  same value list through `jsonschema` against the emitted schema and assert
  identical accept/reject outcomes, so the two constraints cannot drift.

### 5.3 Project-owned single-pass bounds

The builder iterates one `yaml.parse(text, Loader=StrictStrategySafeLoader)`
stream and enforces these fixed ceilings. Every bound is checked incrementally
during iteration, so an offending document is rejected before the stream is
exhausted and before any Python container is completed.

`yaml.parse` is genuinely pre-construction: it is a generator that drives only
`check_event`/`get_event`, so PyYAML's Composer and Constructor are never
entered and no `Node` and no constructed object exists. PyYAML's Scanner and
Parser are non-recursive state machines, so the stream itself can be consumed
to arbitrary depth without `RecursionError`, which is what makes an incremental
depth bound implementable at all.

| Bound | Constant | Value |
|---|---|---|
| Source bytes | `MAX_SOURCE_BYTES` | `262_144` |
| Scalar characters | `MAX_SCALAR_CHARACTERS` | `8_192` |
| Mapping or sequence entries | `MAX_COLLECTION_ENTRIES` | `512` |
| Nesting depth, event stream | `MAX_EVENT_DEPTH` | `32` |
| Nesting depth, expanded value | `MAX_EXPANDED_DEPTH` | `32` |
| Total events | `MAX_EVENT_COUNT` | `20_000` |
| Anchor definitions | `MAX_ANCHORS` | `64` |
| Alias references | `MAX_ALIAS_REFERENCES` | `256` |
| Expanded node budget | `MAX_EXPANDED_NODES` | `50_000` |
| Minimum integer value | `MIN_INTEGER_VALUE` | `-(2**63)` |
| Maximum integer value | `MAX_INTEGER_VALUE` | `2**63 - 1` |
| Expression nesting depth (post-parse, **not** a builder bound) | `MAX_EXPRESSION_DEPTH` | `24` |

`MAX_EXPRESSION_DEPTH` is listed here only so every Stage 4 ceiling has one
home. It is **not** enforced during the event pass: it bounds the validated
`Expression` tree after `StrategySpec` is constructed, and YAML nesting is
already bounded by `MAX_EVENT_DEPTH`. Task 2's "one test per bound in section
5.3" therefore excludes it, and
`tests/unit/strategy/test_strategy_yaml_bounds.py` carries no expression-depth
case; that bound is tested in
`tests/unit/strategy/test_strategy_expressions.py` at the model level and again
by the Task 3 checker.

**Integer magnitude is bounded by value, not by digit count.** CPython 3.12
enforces `sys.get_int_max_str_digits() == 4300`, so `int(text)` raises
`ValueError: Exceeds the limit (4300 digits) for integer string conversion` for
a longer literal — and `canonical_json_bytes` raises the same way through
`json.dumps`. A 4301-to-8192-digit plain integer sits inside
`MAX_SCALAR_CHARACTERS` and would therefore either escape as an uncaught
exception, violating section 5.3.2's "no exception escapes" contract and the
`Result`-only contract of section 5.2, or be swallowed with no code in the
closed section 5.9 table. A digit cap alone would not be enough either: it
would still admit an absurd integer into a permanent `content_hash` and into
`model_validate_json`. The bounds therefore follow the existing repository
precedent `BoundedDetailInteger` in `crypto_lab/domain/diagnostics.py`, which
is signed 64-bit. The classifier checks the bound **before** calling `int()`,
by digit-length pre-check then value comparison, so the CPython limit is never
reached. Out-of-range yields `STRATEGY.YAML_INTEGER_OUT_OF_RANGE`.

#### 5.3.1 Transitive alias-expansion accounting

A raw per-anchor event count is **not** sufficient, because it does not include
the expansion of aliases nested inside that anchor. Nine levels of
`&L[n] [*L[n-1] x9]` is roughly 100 raw events, 81 alias references, 9 anchor
definitions, and depth 2 — inside every raw ceiling — yet denotes about
`9**9` values. Accounting must therefore be **transitive**:

- maintain a stack of open anchor frames, each with a `cost` counter;
- on every **node-producing** event — `ScalarEvent`, `SequenceStartEvent`, and
  `MappingStartEvent` — add `1` to `expanded` and to every open frame's `cost`.
  Framing events charge **nothing**: `StreamStartEvent`, `StreamEndEvent`,
  `DocumentStartEvent`, `DocumentEndEvent`, `SequenceEndEvent`, and
  `MappingEndEvent` produce no node. Charging them would contradict the
  statement below that `expanded` is an exact count of materialised nodes, and
  would make two conforming implementations disagree on the same document;
- on an alias event, look up `expanded_size[name]`; reject with
  `STRATEGY.YAML_RECURSIVE_ALIAS` if the name is unknown or its frame is still
  open; otherwise add that recorded **expanded** cost to `expanded` and to
  every open frame's `cost`;
- check `expanded > MAX_EXPANDED_NODES` immediately after every update and
  reject with `STRATEGY.YAML_EXPANSION_EXCEEDED`;
- when an anchor's node closes, record `expanded_size[name] = frame.cost`, and
  reject if that cost alone exceeds `MAX_EXPANDED_NODES`.

**The expansion mechanism is fixed here, and Appendix H must agree with it.**
An alias is materialised by **deep-copying the already-built value** recorded
for its anchor. There is no event replay. Consequently:

- a replayed or copied node is **never charged again**, because the alias site
  already charged the whole `expanded_size[name]`. Charging both would make
  `expanded` a fiction and move the point at which `MAX_EXPANDED_NODES` fires,
  which is exactly what `invalid/billion_laughs.yaml` is authored to pin;
- an anchored **scalar** records `cost = 1`;
- a collection's own start event is charged to its own frame, so a frame's
  recorded cost is the complete node it denotes;
- `MAX_EXPANDED_DEPTH` is incremented while an alias's copied value is spliced
  in; `MAX_EVENT_DEPTH` is not, because no event is re-emitted.

A test pins the accounting numerically against this exact fixture, because
describing the accounting is not enough — an off-by-one here stays invisible
until the bomb fixture silently stops failing:

```text
a: &x [1, 2]
b: *x
```

Hand-computed under the rules above: the root mapping start charges `1`; key
`a` charges `1`; the anchored sequence charges `1` for its start plus `1` for
each of the two scalars, so `expanded_size["x"] == 3`; key `b` charges `1`; and
the alias charges the recorded `3`. **`expanded == 9`**, and the six framing
events charge nothing. The test asserts exactly `9` and exactly
`expanded_size == {"x": 3}`.

Because the value is built in the same pass, `expanded` is an exact count of
the nodes the builder will materialise, and the expanded-depth counter bounds
the builder's own recursion. `MAX_EXPANDED_NODES` at 50,000 keeps the builder
far below Python's recursion and memory limits. The retained per-anchor value
store is bounded by the same budget, since no anchor's recorded cost may exceed
`MAX_EXPANDED_NODES` and at most `MAX_ANCHORS` of them exist.

`MAX_EVENT_DEPTH` and `MAX_EXPANDED_DEPTH` are both `32`, and expanded depth is
greater than or equal to event depth at every point, so the expanded bound
alone would reject everything the event bound would. Keeping both is defence in
depth against a future change to either constant, not a claim that each catches
cases the other misses.

Rejecting an alias whose anchor is still open makes a recursive or cyclic
structure structurally impossible rather than test-enforced, so the accepted
canonical value is always a finite acyclic tree. A test asserts this directly.

`MAX_ANCHORS` counts anchor **definitions**, not distinct names, so a document
cannot evade it by redefining one name; redefining an anchor name is rejected
outright. A second `DocumentStartEvent` is rejected during the pass with
`STRATEGY.YAML_MULTIPLE_DOCUMENTS`, and a stream containing no document is
rejected with `STRATEGY.YAML_EMPTY_DOCUMENT`.

#### 5.3.2 Required adversarial tests

`invalid/billion_laughs.yaml` must be a **nested** bomb of at least nine
levels, not a flat one; a flat fixture would pass a non-transitive
implementation and hide the defect. Tests must assert:

1. the nested bomb is rejected with `STRATEGY.YAML_EXPANSION_EXCEEDED`;
2. rejection occurs **mid-stream**, proven by instrumentation rather than by
   absence. Asserting that `yaml.compose`, `yaml.compose_all`, `yaml.load`, and
   `yaml.safe_load` are never called proves nothing here: they are never called
   for any input, so the assertion holds equally for an implementation that
   collects every event into a list and only then checks its bounds. Instead,
   wrap `yaml.parse(...)` in a counting generator, run the nested bomb, and
   assert both that the number of events consumed is strictly less than the
   document's total event count, and that the generator was closed while
   unexhausted — a sentinel appended after the final event must never be
   reached, and `gen.gi_frame is None` after the `contextlib.closing` block;
3. expanded depth beyond `MAX_EXPANDED_DEPTH` is rejected even when event-stream
   depth stays under `MAX_EVENT_DEPTH`, using an alias-composed fixture;
4. `&a [*a]` is rejected with `STRATEGY.YAML_RECURSIVE_ALIAS`;
5. an alias to a never-defined name is rejected;
6. a redefined anchor name is rejected.

Every rejection returns a `Result` failure carrying at least one `Diagnostic`
with `category = SCHEMA_VALIDATION` or `SECURITY`, the exact error code, and
bounded details containing only the integer line and column. No exception
escapes, including `RecursionError`, which the expanded-depth bound makes
unreachable.

### 5.3.3 Deterministic diagnostic identity

`Diagnostic` requires `diagnostic_id: DiagnosticId` (a canonical lowercase
UUID4) and `timestamp_utc: UtcDateTime`, both mandatory. Section 5.4 forbids
every random and wall-clock source, and `Clock` and `ContentHasher` remain in
`_DEFERRED_DEFINITIONS`, so neither `uuid.uuid4()` nor `datetime.now` is
available. Without an explicit mechanism the loader could not emit a valid
`Diagnostic` at all, and Task 6's byte-identical-result property would be
unsatisfiable. Stage 4 resolves this as follows:

1. **Identity is derived, never drawn.** `diagnostic_id` is
   `"diag_" + _uuid4_shaped(profile_hash(HashingProfile.DIAGNOSTIC_IDENTITY_V1,
   payload))`, where `payload` is the diagnostic's **complete** material
   content: `schema_version`, `error_code`, `category`, `severity`,
   `source_component`, `message`, `retriable`, `details`, and any correlation
   IDs. `retriable` and `schema_version` are included deliberately — omitting
   `retriable` would collide two genuinely different diagnostics onto one
   `diagnostic_id`. `timestamp_utc` and `causal_diagnostic_ids` are excluded
   deliberately: the first is not material identity, and the second would make
   the payload self-referential. This payload **is** the deduplication key
   required by section 5.4, so identical identity implies identical diagnostic
   and deduplication cannot drop a distinct one. That matters beyond tidiness:
   `Diagnostic.validate_causes` rejects a diagnostic that directly causes
   itself, so an identity collision between a diagnostic and one of its causes
   would raise a `ValidationError` out of a failure path. `_uuid4_shaped` takes the first 32 hex
   digits of the digest, forces the version nibble to `4` and the variant
   nibble into `[89ab]`, and formats the canonical `8-4-4-4-12` grouping, so
   `validate_prefixed_uuid4` accepts it. Identical diagnostic content therefore
   always yields an identical ID, which is what makes the resolver property in
   Task 6 achievable.
2. **Time is a parameter, never ambient.** `observed_at_utc: datetime` is an
   explicit parameter of `load_yaml_document`, `StrategyLoader.load`, and every
   `capabilities` entry point that can emit a diagnostic, and is passed through
   to `timestamp_utc`. The resolver takes it from
   `RuntimeAvailabilityObservation.observed_at_utc`, which specification
   section 11.3 already requires, so `resolve` gains no parameter beyond the
   section 8.2 signature.
3. **Task 2** adds `DIAGNOSTIC_IDENTITY_V1 = "diagnostic-identity/v1"` and the
   `_uuid4_shaped` helper to `crypto_lab/domain/hashing.py`, because Task 2 is the
   first task that emits a `Diagnostic`. Task 5 later adds `STRATEGY_VERSION_V1`
   to the same enum.
4. Tests assert that two independent runs over equal inputs produce
   byte-identical `Result` failures, including IDs, and that no Stage 4 module
   imports `uuid`, `random`, or `time`.

### 5.4 Determinism

- All canonical arithmetic uses a local `decimal.Context(prec=34,
  rounding=ROUND_HALF_EVEN)` applied with `decimal.localcontext(...)`. The
  process-global Decimal context is never mutated.
- Division by zero, overflow beyond declared schema bounds, and invalid
  operations produce deterministic diagnostics rather than exceptions,
  infinities, or NaN. Non-finite results are rejected.
- Every diagnostic collection is deduplicated and sorted by a fixed key before
  return, so identical inputs always yield byte-identical output.
- No wall-clock, filesystem, network, environment, hash-seed, or random source
  is read anywhere in Stage 4 code.

#### 5.4.1 Bounded diagnostic output — reviewed correction

`Failure.diagnostics` is `min_length=1, max_length=256` in
`crypto_lab/domain/results.py`, and `MAX_RESULT_DIAGNOSTICS = 256`. **Both are
preserved unchanged.** No Stage 4 task widens, narrows, or removes that bound,
and no Stage 4 task modifies `domain/results.py` for this policy: `Failure`
itself is **not** changed. The problem this subsection closes is that a validator
can legitimately find more than 256 distinct defects, and the three obvious
responses are all forbidden — raising violates the `Result`-only contract,
returning 257 items violates `Failure`, and slicing to 256 silently is
indistinguishable to a consumer from "there were exactly 256".

**The contract.**

0. **Two entry conditions make identity well behaved.** Every diagnostic entering
   a bounded Stage 4 combiner carries **no correlation ID** — `experiment_id`,
   `run_id`, `invocation_id`, and `engine` are all absent — and an **empty**
   `causal_diagnostic_ids`. Both constraints are load-bearing rather than
   incidental, because section 5.3.3 *includes* "any correlation IDs" in the
   identity payload while deliberately *excluding* `causal_diagnostic_ids` from
   it. Without the first, two diagnostics agreeing on error code and details but
   differing in a correlation ID would receive different identities, survive
   deduplication, and then tie on any content key. Without the second, two
   diagnostics differing **only** in `causal_diagnostic_ids` would share one
   identity, so which payload survived deduplication would depend on arrival
   order. Neither hazard is reachable once both constraints hold, and Stage 4
   emits no correlated or causally linked diagnostic anywhere, so nothing is
   given up.
1. **Deduplicate first, bound second.** Deduplication happens **before** the
   output bound is applied, so the bound is counted in *unique* diagnostics.
   Under item 0 the section 5.3.3 identity payload reduces to a function of
   `(error_code, source_component, details)`, so equal identity means a
   byte-identical diagnostic and deduplication can never drop a distinct one.
2. **Order is a documented total order.** Substantive diagnostics are emitted in
   the producing entry point's own documented stable ordering, declared in that
   entry point's task section. The key must be a **total** order over material
   content, so no tie can be resolved by generation order and no source
   permutation can change the retained set or its sequence. A key that leaves a
   genuine tie is not acceptable, because a permutation test over a tying key
   passes vacuously.
3. **0 unique diagnostics** → `Success`. `Failure` requires at least one
   diagnostic, so an empty finding set is never a `Failure`.
4. **1 through 256 unique diagnostics** → a `Failure` carrying **every** unique
   diagnostic, in canonical order, with **no** marker. Diagnostics are complete
   in this range.
5. **257 or more unique diagnostics** → a `Failure` carrying exactly **256**
   entries: the **first 255** substantive diagnostics in canonical order,
   followed by **one** terminal diagnostic-limit marker.
6. **The marker is always last.** Its position is the signal, so it is appended
   after ordering and is never itself sorted into the substantive run.
7. **Silent truncation is forbidden.** A consumer must be able to distinguish
   "exactly 256 defects" from "at least 257 defects" by inspecting the returned
   tuple alone, with no out-of-band information.
8. **Expected validation overflow never raises.** Crossing the bound is an
   ordinary, expected outcome of an adversarial or badly authored strategy. It
   produces a `Result` failure, never a `ValidationError`, `IndexError`, or any
   other exception escaping the entry point.

**The marker contract**, fixed exactly:

| Field | Value |
|---|---|
| `error_code` | `STRATEGY.DIAGNOSTIC_LIMIT_REACHED` |
| `severity` | `ERROR` |
| `category` | `SCHEMA_VALIDATION` — chosen deliberately. `Diagnostic.validate_causes` requires an `invocation_id` for `ENGINE_RUNTIME`, `PROTOCOL`, `TIMEOUT`, and `CANCELLATION`, and item 0 forbids correlation IDs, so those four are unavailable. `INTERNAL_INVARIANT` would misdescribe an expected outcome, and `SECURITY` is reserved for adversarial nesting bounds. The marker reports that a schema-validation pass exceeded its own output contract, so it stays with the pass that produced it |
| `message` | one fixed bounded literal, never interpolated from input |
| `retriable` | `false` |
| `timestamp_utc` | the entry point's explicit `observed_at_utc`, per section 5.3.3 item 2 |
| `source_component` | the producing module's own fixed literal component name |
| `details` | deterministic, equivalent to `diagnostic_limit = 256` and `retained_diagnostics = 255`, and nothing else |
| `diagnostic_id` | derived from that complete payload exactly as section 5.3.3 requires |
| `causal_diagnostic_ids` | empty |

**No omitted count.** `details` carries no "omitted" or "total" figure. The
combiner is permitted to **stop generating** once it holds the 257th unique
diagnostic, which is what makes the bound a work bound and not merely an output
bound; a combiner that stops there provably does not know the true total, so
publishing one would be a fabricated number. An omitted count may be added only
if it is separately calculated through a proven bounded process, and no Stage 4
task is authorized to add one.

**The boundary is intentionally discontinuous.** At 256 unique diagnostics the
result carries 256 substantive entries; at 257 it carries 255 substantive entries
plus the marker, so crossing the boundary drops one more substantive diagnostic
than arithmetic alone requires. That is deliberate: `retained_diagnostics` is
fixed at 255 by the marker contract above, which keeps the marker's payload — and
therefore its derived `diagnostic_id` — constant for every overflow size instead
of varying with a count the combiner may not know. This is recorded so it is not
read as an off-by-one.

**Diagnostic completeness, stated exactly.** Wherever this plan describes a
bounded entry point's diagnostics, the governing statement is:

> Diagnostics are complete when the unique diagnostic count is at most 256.
> Beyond that bound, the result returns the first 255 substantive diagnostics in
> canonical order plus the explicit terminal diagnostic-limit marker.

That sentence supersedes any absolute claim of unconditional completeness for a
bounded entry point. For the record, Task 4's own section contained no such
absolute claim before this correction — the "complete feature and signal series"
language in section 5.6 and Task 4 is about **series**, not diagnostics, and is
unaffected — so nothing was silently rewritten and the sentence above is stated
rather than substituted.

**This subsection also amends section 5.4 bullet 3 on sortedness, and the
amendment is stated rather than left implicit.** Bullet 3 requires every
diagnostic collection to be "deduplicated and sorted by a fixed key before
return". Item 6 above appends the marker **after** ordering, and
`STRATEGY.DIAGNOSTIC_LIMIT_REACHED` would sort **first** among the `STRATEGY.*`
codes on any error-code-leading key, so a wholly sorted tuple is incompatible
with a terminal marker. The amended rule is therefore: the returned tuple is the
deduplicated, canonically sorted substantive run, followed — when and only when
the bound is exceeded — by the single terminal marker. Determinism is unaffected,
because the marker's presence and position are both fixed functions of the unique
diagnostic count.

**Scope, and Task 3 is not reopened.** This policy is introduced by the present
correction and binds the **Task 4 diagnostic combiner** and every later Stage 4
entry point whose unique diagnostic count can exceed the bound. Task 3's
committed `validate_strategy_expressions` predates it: that function truncates
its sorted, deduplicated prefix at exactly `MAX_RESULT_DIAGNOSTICS`, so it
returns at most 256 diagnostics and **does not violate `Failure`'s bound**. It is
explicitly **not** reopened by this correction, and Task 4 must not modify it
unless a focused regression proves that its own implementation independently
violates the 256-diagnostic contract. Aligning it with the marker policy is a
separate scope ruling, not Task 4 work.

#### 5.4.2 Task 3 diagnostic bounding — reviewed correction, supersedes the paragraph above

**The separate scope ruling anticipated above has been granted.** The paragraph
immediately preceding this subsection is superseded on exactly one point: Task 3's
`validate_strategy_expressions` is now **required** to apply the same bounded
output policy as every other Stage 4 producer. Everything else it says stands —
in particular that Task 3 never violated `Failure`'s `max_length`.

**The defect, stated precisely.** Truncating a sorted, deduplicated prefix at
exactly `MAX_RESULT_DIAGNOSTICS` is *silent*. A caller receiving 256 diagnostics
cannot distinguish a specification with exactly 256 unique defects from one with
20,000, because no marker distinguishes them and no count is published. Section
5.4.1 item 5 forbids exactly that for the Task 4 combiner; there is no principled
reason the same output contract should differ by producer, and a caller that
merges the two would inherit two incompatible truncation semantics.

**Required behaviour.** `validate_strategy_expressions` must, in this exact order:

1. **Collect** its bounded-input findings, as it does today. Every finding source
   is already bounded by `MAX_RULES` and `MAX_EXPRESSION_DEPTH`, so collecting all
   of them is itself bounded work.
2. **Deduplicate** by `diagnostic_id`, which section 5.3.3 derives from the
   complete material payload.
3. **Canonically sort** by the total key fixed below.
4. **Return all** unique diagnostics when the count is at most
   `MAX_RESULT_DIAGNOSTICS`.
5. **Return the first `MAX_RESULT_DIAGNOSTICS - 1` plus the terminal
   `STRATEGY.DIAGNOSTIC_LIMIT_REACHED` marker** when the count exceeds
   `MAX_RESULT_DIAGNOSTICS`, with the marker **last**.

It must never silently truncate, never raise for an expected diagnostic overflow,
and never modify `Failure`, `MAX_RESULT_DIAGNOSTICS`, or `domain/results.py`. **No
second diagnostic-limit code is introduced**: the marker is the existing
`STRATEGY.DIAGNOSTIC_LIMIT_REACHED` of section 5.4.1, emitted with
`source_component = "strategy.validation"` rather than
`"strategy.feature_graph"`.

**The combiner must absorb an inherited marker — reviewed correction to this
correction.** Giving Task 3 a marker creates a hazard that the first draft of this
subsection got wrong, so it is fixed here explicitly rather than left to
implementation. `validate_feature_graph` re-sorts **every** inherited diagnostic by
section 5.4.1's key, which leads on `error_code`; `D` precedes `E`, `F`, `P` and
`R`, so a marker emitted by Task 3 would sort to **index 0** of the combiner's
substantive run. That directly contradicts section 5.4.1 item 6 — the marker "is
never itself sorted into the substantive run" — and the sortedness amendment above,
which fixes the returned tuple as the sorted substantive run followed by **the
single** terminal marker. It is reachable from a specification a committed test
already builds: 320 unique Task 3 findings become 255 plus a marker, the graph
contributes none, so the combiner would see exactly 256 unique diagnostics, take
its complete-output path, and return a tuple whose marker sits **first** and whose
terminal position holds a substantive diagnostic. The positional signal would be
exactly inverted, and at 257 or more there would be two markers, one mid-run.

The combiner therefore, before ordering:

1. **Partitions** its combined input into substantive diagnostics and any
   `STRATEGY.DIAGNOSTIC_LIMIT_REACHED` markers, from any `source_component`.
2. Records `inherited_overflow` as true when at least one such marker was present.
3. Deduplicates and canonically sorts **only** the substantive run.
4. Returns the substantive run unchanged when its unique count is at most
   `MAX_RESULT_DIAGNOSTICS` **and** `inherited_overflow` is false.
5. Otherwise returns the first `MAX_RESULT_DIAGNOSTICS - 1` substantive
   diagnostics plus **exactly one** terminal marker, which the combiner emits under
   its own `source_component`.

An inherited marker therefore forces a terminal marker even when the combiner's own
substantive count is small, which is the honest outcome: an upstream producer
truncated, so the returned set is provably incomplete and must say so. Exactly one
marker is ever returned, it is always last, and "at most 256 and complete" remains
distinguishable from "bounded" by the tuple alone. The rule is re-entrant: a marker
already bearing the combiner's own `source_component` is absorbed too, because
step 1 partitions markers from **any** producer.

**This amends section 5.4.1 items 4 and 5, and the amendment is stated rather than
left implicit**, exactly as that subsection requires of its own amendment to
section 5.4 bullet 3. Item 4 as written returns every unique diagnostic with **no**
marker for a count of 1 through 256, and item 5 triggers only above 256. Two things
change:

1. **The counting basis** is the unique **substantive** diagnostic count — markers
   are partitioned out before the count is taken, and are never themselves counted
   toward the bound.
2. **Item 5's trigger widens** to *the substantive count exceeds the bound **or** a
   marker was absorbed*. Item 4's no-marker guarantee correspondingly narrows to
   *at most 256 substantive **and** nothing absorbed*.

Item 4's "carrying every unique diagnostic" is likewise read as every unique
substantive diagnostic: an absorbed marker is not dropped information, it is
**replaced** by the combiner's own terminal marker, which carries the same meaning
under the correct `source_component` and in the correct position.

**One committed Task 3 test is invalidated by this subsection, and it is named here
for the same reason section 5.10 names the three that ruling invalidates.**
`test_the_diagnostic_count_is_bounded_by_the_result_contract` builds 320 unique
findings and then comprehends `diagnostic.details["rule_id"]` over every returned
diagnostic. Once the marker occupies the last slot that comprehension meets a
diagnostic whose details are `diagnostic_limit` and `retained_diagnostics`, and
raises `KeyError` — a hard error, not an assertion drift, because the length
assertion still holds. It must be updated to exclude the marker, or to assert the
marker's own contract explicitly.

**Task 3's total ordering key, and why it is not section 5.4.1's key.** Task 3
sorts by

```text
(rule_id, node_path, error_code, canonical_json_bytes(details))
```

The first three components are Task 3's **existing reviewed key**, unchanged, so
every committed ordering guarantee is preserved byte for byte — a reader still
sees diagnostics grouped by rule, then by node path, then by code, and the
committed tests that pin that order stay green. The fourth component is added
because the three-part key alone is **not total**: an entry rule and an exit rule
may share an identifier, and two such findings at the same `node_path` with the
same `error_code` differ only in `details.rule_collection`, so they tie. Section
5.4.1 item 2 rules that a key admitting a genuine tie is unacceptable, because a
permutation test over it passes vacuously. The fourth component removes the last
tie without disturbing the first three.

**Spec-level findings.** A finding that attaches to no rule has no `rule_id` and no
`node_path`, so this key needs a convention for them. **Section 5.10 fixes it**: a
spec-level finding takes the empty string for both leading components, in the key
only and never in `details`, which sorts it before every rule-level finding because
`NormalizedIdentifier` requires a leading lowercase letter. The only spec-level code
this correction introduces is `STRATEGY.REFERENCE_NAMESPACE_COLLISION`.

Section 5.4.1's combiner key `(error_code, source_component,
canonical_json_bytes(details))` is deliberately **not** adopted here. That key
exists to merge diagnostics from several producers, which is the combiner's
problem and not Task 3's — Task 3 has exactly one `source_component`. Both keys
are total; each is total for its own producer's payload.

**The decisive reason is that adopting it would be pure churn.**
`validate_feature_graph` **re-sorts every inherited Task 3 diagnostic** with
section 5.4.1's key, so Task 3's own order is observable **only** to a direct
caller of `validate_strategy_expressions` and is discarded the moment the combiner
runs. Re-keying Task 3 would therefore churn that single surface and change nothing
downstream. A second reason, weaker but real: because the four-part key is a strict
**refinement** of the committed three-part key, the Task 3 step's committed
statement that diagnostics are "sorted by `(rule_id, node_path, error_code)`"
remains literally true, which the alternative cannot claim.

For accuracy about cost, since an earlier draft of this subsection overstated it:
adopting section 5.4.1's key would break **two** committed assertions — the
simultaneous-defect ordering test and the rule-id ordering test, the latter because
`"entry_rules" < "exit_rules"` inverts it — plus one docstring. It is **not** four
tests. The overstated figure is withdrawn; it was never the load-bearing reason, and
the re-sort argument above is.

**Ownership.** This is a correction to Task 3's committed implementation,
authorized by this ruling and by nothing else. It does not reopen Task 3's scope
generally: no other Task 3 behaviour, message, code, or detail field changes.

### 5.5 Strategy identity

`StrategyVersion.content_hash` is
`profile_hash(HashingProfile.STRATEGY_VERSION_V1, payload)`.
`profile_hash` is typed `payload: dict[str, JsonValue]` and
`CanonicalHashEnvelope` is `strict=True`, so a `BaseModel` and a `tuple` are
both invalid there. Following the Stage 3 convention in
`crypto_lab/datasets/hashing.py`, the payload is built with
`model_dump(mode="json")` and `cast(JsonValue, ...)`, and every sequence is a
`list`. The payload contains exactly:

1. `strategy_spec` — `spec.model_dump(mode="json")` with no exclusions, since
   `StrategySpec` holds no self-hash field.
2. `strategy_schema_version` — the `StrategySpec.schema_version` literal.
3. `expression_semantics_version` — `"expressions/v1"`.
4. `hashing_profile_version` — `"strategy-version/v1"`.
5. `extension_hashes` — a `list[str]` of declared extension-module
   `content_hash` values, sorted by `(adapter_name, extension_id, version)`.

The payload deliberately excludes, and tests prove it excludes: YAML comments;
harmless whitespace; mapping key order; the source path or `source_name`;
parsing wall-clock time; machine identity; and any ambient value.
`strategy_version_id`, `created_at_utc`, and the source-provenance record are
external to the hashed payload and are therefore not self-hash fields.

`StrategySourceProvenance` records `source_name` (a bounded label, never a
filesystem path), `source_bytes_sha256`, `source_byte_length`, and
`observed_at_utc`. It is retained for audit and is explicitly outside the
identity payload.

### 5.6 Level 1 evaluator constraints

The evaluator is pure, deterministic, fixture-sized, offline, engine-neutral,
Decimal-aware, explicit about missing values and warm-up, and independent from
any trading engine. It is **not** an order simulator, fill simulator, portfolio
simulator, or real backtesting engine. It takes an explicit in-memory bar
series and returns complete feature and signal series. It has no wall-clock,
filesystem, network, engine, or random-number access. Input series are bounded
to `MAX_EVALUATION_BARS = 4_096`.

### 5.7 Dependency direction — resolved by relocation, not by a new edge

Specification section 8.2 places `descriptor: AdapterDescriptor` and
`comparison_level: ComparisonLevel` in `CompatibilityResolver.resolve`, while
section 8's graph and the section 27.1 table give `capabilities` exactly one
allowed inward dependency: `domain`.

An earlier draft of this plan proposed reading 27.1's column as a floor and
adding a type-only `capabilities -> adapters` edge. **That resolution is not
available.** Specification section 27.1 states: *"The dependency direction
table is normative."* Roadmap section 2 places specification section 27 in the
global normative floor for every stage, and roadmap section 3 restates it. A
table the specification declares normative cannot be reinterpreted by an
implementation plan.

The specification supplies its own remedy. Section 8.2 states: *"Names may move
between files during implementation planning, but parameters, ownership,
sync/async behavior, and result semantics must remain equivalent."* Relocation
is authorized by name; adding a graph edge is not. Section 11.3 already
classifies `EngineDescriptor`, `AdapterDescriptor`, and
`RuntimeAvailabilityObservation` as canonical **domain-model** required
records, so `domain` is their legitimate home.

Stage 4 therefore relocates the shared canonical contract types into
`crypto_lab/domain/`:

1. `CapabilityName` and `VocabularyVersion` move to
   `crypto_lab/domain/capability_names.py`.
2. `EngineDescriptor`, `AdapterDescriptor`, `SupportedSchemaVersion`, and
   `OperatingSystem` move to `crypto_lab/domain/descriptors.py`.
3. `ComparisonLevel` is defined in `crypto_lab/domain/comparison_levels.py`,
   **not** in `capabilities`. This is required, not cosmetic: `ComparisonLevel`
   is also a field of `ExperimentSpec`, `MetricValue`, and `EngineRunRequest`,
   and specification section 27.2 places `EngineRunRequest` in
   `adapters/envelopes.py`. Leaving it in `capabilities` would force an
   `adapters -> capabilities` edge at Stage 6 and break 27.1 a second time.
   Specification section 11.5 already lists `CompatibilityOutcome` among the
   normative domain enums, so this placement follows the established pattern.
4. `RuntimeAvailabilityObservation` is defined in
   `crypto_lab/domain/descriptors.py` for the same reason.
5. `crypto_lab/adapters/descriptors.py` imports and re-exports every relocated
   name, so its public surface and every existing import site are unchanged.
   This preserves 27.1's *Responsibility* column (`adapters` still owns and
   exposes descriptor contracts) while the relocation preserves its *Allowed
   inward dependencies* column. Relocation satisfies both columns; a new edge
   satisfies neither.
6. **`CapabilityRequirement` and its `ApproximationPolicy` move to
   `crypto_lab/domain/capability_requirements.py`, and Task 2 owns them.**
   Specification section 12.2 makes `required_capabilities` a `StrategySpec`
   field and section 12.4 renders it as `{capability, required}` entries, which
   section 11.3 defines as exactly `CapabilityRequirement`. Leaving that type in
   `capabilities/models.py` would force `strategy` to import from
   `capabilities`, violating the same normative 27.1 row this section exists to
   protect and failing the Task 6 architecture test in item 11 below. It would
   also invert task order, since `StrategySpec` is Task 2 and `capabilities` is
   Task 6. Section 11.3 already classifies `CapabilityRequirement` as a
   canonical domain record, so relocation is authorized by exactly the argument
   used above for `AdapterDescriptor`. `capabilities/models.py` re-exports it,
   keeping its public surface intact. For the same reason **Task 2**, not Task
   6, creates `domain/capability_names.py` and `domain/comparison_levels.py`:
   `StrategySpec.required_capabilities`, `supported_approximation_policy`, and
   `comparison_requirements` all need those types.
7. `crypto_lab.capabilities` imports **nothing** from `crypto_lab.adapters`.
   Task 6 adds an architecture test asserting exactly that, plus that
   `capabilities` imports nothing from `experiments`, `datasets`, `artifacts`,
   `persistence`, `process_supervision`, `configuration`, `audit`, or `cli`.

**Byte-identity is provable, not hoped for.** The generated
`schemas/protocol/adapter-descriptor-v1.schema.json` keys its `$defs` by bare
class and alias names — `EngineDescriptor`, `NormalizedIdentifier`,
`OperatingSystem`, `SemanticVersion`, `Sha256`, `SupportedSchemaVersion` —
never by module path, and `capability_vocabulary_version` and the capability
tuples are inlined with no `$def` at all. Relocating the definitions therefore
cannot change the emitted bytes. Task 6 step 12 keeps `schema-generate-check`
as a blocking gate proving it.

This is recorded as an escalated architecture conflict resolved under section
2's authority order, in favour of the specification over the earlier plan
reading — not as a reinterpretation of a normative table.

### 5.8 Stage 4 / Stage 9 comparison-service boundary

Specification section 25.4 places `ComparisonEligibilityService` in
`experiments/comparison.py`, and roadmap Stage 5 also lists section 25.4.
Stage 4 owns **contracts only**:

- `ComparisonLevel`, `ComparisonEligibilityOutcome`,
  `ComparisonEligibilityResult`, `ComparisonIneligibilityReason`,
  `DifferenceCategory`, and the deterministic reason-ordering rules;
- the pure eligibility predicate over two already-validated comparison inputs.

The `ComparisonEligibilityService` class in `crypto_lab/experiments/comparison.py`
is owned by the later stage that owns `RunManifest`. On current roadmap
evidence that is **Stage 9**, not Stage 5: roadmap Stage 5's deliverables and
schema permission cover experiment, run, invocation, retry, and lifecycle
contracts only, and `RunManifest` first appears in Stage 9's exit evidence,
consistent with specification section 11.3 describing it as core-generated
after result finalization. Stage 4 defines no `RunManifest` and no service
class, and `ComparisonEligibilityService` therefore stays in
`_DEFERRED_DEFINITIONS`.

### 5.9 Closed error-code table

Stage 4 emits only these `ErrorCode` values. Any addition requires a plan
amendment.

```text
STRATEGY.SOURCE_TOO_LARGE            STRATEGY.SOURCE_NOT_UTF8
STRATEGY.SOURCE_BOM_PRESENT          STRATEGY.SOURCE_NOT_IN_MEMORY
STRATEGY.SOURCE_NAME_INVALID
STRATEGY.YAML_SYNTAX                 STRATEGY.YAML_MULTIPLE_DOCUMENTS
STRATEGY.YAML_EMPTY_DOCUMENT         STRATEGY.YAML_FORBIDDEN_TAG
STRATEGY.YAML_DUPLICATE_KEY          STRATEGY.YAML_MERGE_KEY_FORBIDDEN
STRATEGY.YAML_SCALAR_TOO_LONG        STRATEGY.YAML_COLLECTION_TOO_LARGE
STRATEGY.YAML_DEPTH_EXCEEDED         STRATEGY.YAML_EVENT_BUDGET_EXCEEDED
STRATEGY.YAML_ANCHOR_BUDGET_EXCEEDED STRATEGY.YAML_ALIAS_BUDGET_EXCEEDED
STRATEGY.YAML_EXPANSION_EXCEEDED     STRATEGY.YAML_RECURSIVE_ALIAS
STRATEGY.YAML_NONCANONICAL_SCALAR    STRATEGY.YAML_ANCHOR_REDEFINED
STRATEGY.YAML_MAPPING_KEY_INVALID    STRATEGY.YAML_INTEGER_OUT_OF_RANGE
STRATEGY.YAML_DIRECTIVE_FORBIDDEN
STRATEGY.SCHEMA_INVALID              STRATEGY.UNKNOWN_FIELD
STRATEGY.EXPRESSION_UNKNOWN_OP       STRATEGY.EXPRESSION_TYPE_MISMATCH
STRATEGY.EXPRESSION_ARITY            STRATEGY.EXPRESSION_DEPTH_EXCEEDED
STRATEGY.REFERENCE_UNKNOWN           STRATEGY.REFERENCE_NEGATIVE_OFFSET
STRATEGY.REFERENCE_FUTURE_BAR        STRATEGY.FEATURE_DUPLICATE_ID
STRATEGY.FEATURE_UNKNOWN_OPERATION   STRATEGY.FEATURE_CYCLE
STRATEGY.FEATURE_WARM_UP_TOO_SMALL   STRATEGY.PARAMETER_OUT_OF_BOUNDS
STRATEGY.EXTENSION_DECLARATION       STRATEGY.POLICY_FORBIDDEN_MARKET
STRATEGY.POLICY_FORBIDDEN_DIRECTION  STRATEGY.EVALUATION_DIVIDE_BY_ZERO
STRATEGY.EVALUATION_NON_FINITE       STRATEGY.EVALUATION_SERIES_TOO_LONG
STRATEGY.EVALUATION_MISSING_INPUT    STRATEGY.DIAGNOSTIC_LIMIT_REACHED
STRATEGY.REFERENCE_NAMESPACE_COLLISION
CAPABILITY.UNKNOWN_NAME              CAPABILITY.VOCABULARY_VERSION
CAPABILITY.DECLARATION_OVERLAP       CAPABILITY.REQUIREMENT_UNMET
CAPABILITY.APPROXIMATION_DISALLOWED  CAPABILITY.APPROXIMATION_MISSING
CAPABILITY.LEVEL_PREVENTED           CAPABILITY.RUNTIME_UNAVAILABLE
CAPABILITY.POLICY_LIVE_RUNTIME       CAPABILITY.POLICY_FORBIDDEN_REQUEST
COMPARISON.LEVEL_UNSUPPORTED         COMPARISON.STRATEGY_HASH_MISMATCH
COMPARISON.DATASET_HASH_MISMATCH     COMPARISON.ASSUMPTION_MISMATCH
COMPARISON.APPROXIMATION_EXCLUDES_LEVEL
COMPARISON.SCHEMA_VERSION_MISMATCH   COMPARISON.METHODOLOGY_MISMATCH
```

**Reviewed correction — exactly one code added.**
`STRATEGY.DIAGNOSTIC_LIMIT_REACHED` is the sole addition to this closed table
since the plan was approved. It is the terminal diagnostic-limit marker defined
in section 5.4.1, and it is the only code that correction introduces. No other
code is added, and none is removed — `STRATEGY.REFERENCE_FUTURE_BAR` in
particular remains reserved per section 6.5.2. Any further addition still
requires a plan amendment.

**Second reviewed correction — exactly one further code added.**
`STRATEGY.REFERENCE_NAMESPACE_COLLISION` is the second and only other addition
since approval. It is the reference-namespace disjointness code defined in section
5.10, and that correction introduces no other code. The table therefore stands at
its approved contents plus exactly these two. Nothing is removed. Any further
addition still requires a plan amendment.

### 5.10 Reference namespace disjointness — reviewed correction

**The defect this closes.** `NormalizedIdentifier` permits a dot, so `bar.close` is
a syntactically valid `FeatureDefinition.id` and a valid parameter key. Nothing
rejected such a declaration, and the layers then disagreed about what the name
meant: static validation resolved a source bar field first, while the evaluator's
input resolution preferred a declared feature. A specification could therefore
validate with **no diagnostic at all** while two byte-identical feature
declarations produced different series, decided only by how their identifiers
sorted. Reference precedence is not a fix for that; it merely picks a winner for an
ambiguity that should never have been representable.

**The ruling.** For `expressions/v1` the three declaration namespaces are
**pairwise disjoint**:

```text
SOURCE_FIELD    FEATURE    PARAMETER
```

`SOURCE_FIELD` contains **exactly** these six names, and no others:

```text
bar.open   bar.high   bar.low   bar.close   bar.volume   bar.timestamp_utc
```

A specification is rejected when any of the following holds:

1. a declared feature identifier equals a source-field name;
2. a declared parameter identifier equals a source-field name;
3. a declared feature identifier equals a declared parameter identifier.

**The `bar.` prefix is deliberately NOT reserved.** Only the six exact names above
are reserved. A feature or parameter named `bar.midpoint`, `bar.close_ema`, or
`barrier` is unaffected, because reserving a prefix would forbid names the approved
model permits and would be a wider change than the ambiguity requires. Membership
is tested by exact string equality against the closed six-name set.

**Diagnostic.** One `STRATEGY.REFERENCE_NAMESPACE_COLLISION` per **distinct
conflicting name** — never one per namespace pair, and never one per declaration
site, so a name colliding across all three namespaces still yields exactly one
diagnostic. Severity `ERROR`, category `SCHEMA_VALIDATION`, a fixed bounded
message interpolating no input, and deterministic details:

| Detail | Value |
|---|---|
| `reference_name` | the exact colliding name |
| `namespaces` | the namespaces that claim it, in the fixed order below |

Namespace order in `namespaces` is fixed as `SOURCE_FIELD`, `FEATURE`,
`PARAMETER`, independent of declaration order, so the detail payload — and
therefore the derived `diagnostic_id` — is a function of the declaration set
alone.

**`details` is exactly those two keys.** A namespace collision is a **spec-level**
defect: it attaches to no rule, no rule collection, and no expression node.
It therefore carries **no** `rule_collection`, `rule_id`, or `node_path` detail,
unlike every rule-level Task 3 finding, and it must not be constructed through the
per-rule finding helper that injects them.

**Its position in section 5.4.2's sort key is fixed here, because that key leads on
`rule_id` and `node_path` which a spec-level finding does not have.** A spec-level
finding takes the **empty string** for both components of the key. The empty string
sorts before every `NormalizedIdentifier`, whose pattern requires a leading
lowercase letter, so **every namespace-collision diagnostic precedes every
rule-level diagnostic**, deterministically and without a tie: two namespace
findings differ in `reference_name`, hence in `canonical_json_bytes(details)`, which
is the key's fourth component. Those empty strings exist **only** in the sort key
and never in `details`.

**Interaction with duplicate-feature detection.** `STRATEGY.FEATURE_DUPLICATE_ID`
remains **independent**: neither diagnostic masks or gates the other. Precisely,
because the two checks live in different modules, a specification declaring
`bar.close` twice as a feature yields **both** diagnostics from
`validate_feature_graph`, which combines them, and yields the namespace collision
alone from `validate_strategy_expressions`, which does not own duplicate-ID
detection. Neither entry point suppresses a diagnostic the other would report.

**Fail-closed requirement.** A namespace-invalid specification must not produce a
successful feature series or signal series. `validate_feature_graph` inherits
Task 3's diagnostics and returns `Failure` when any are present, so it yields no
`FeatureGraph` and the validated Task 4 path cannot be entered. Stated precisely,
because `evaluate_level_one` is public and accepts a **caller-supplied**
`FeatureGraph`: the guarantee is that no graph obtained **from validation** can
carry a namespace-invalid specification into evaluation. A caller that fabricates a
`FeatureGraph` by hand has left the validated path, exactly as the evaluator's own
committed tests acknowledge. This must be proven by test, not assumed.

**Three committed Task 3 tests are invalidated by this ruling, and inverting them
is required rather than incidental.** They currently assert that a collision is
*accepted* under the precedence rule this ruling replaces with rejection:

- `test_a_source_bar_field_outranks_a_colliding_feature` (rule 1);
- `test_a_source_bar_field_outranks_a_colliding_parameter` (rule 2);
- `test_a_declared_feature_outranks_a_colliding_parameter` (rule 3).

Each must become a rejection test naming
`STRATEGY.REFERENCE_NAMESPACE_COLLISION`. A fourth,
`test_the_losing_side_of_each_precedence_edge_is_genuinely_boolean`, keeps passing
because its probes use non-colliding names, but its docstring claim to guard "the
three tests above" must be corrected.

**Why this is not the asymmetry it resembles.** Section 5.4.2 declines section
5.4.1's combiner key partly *because* it would break committed Task 3 tests, while
this ruling breaks three. The distinction is that there the breakage would be
**gratuitous** — no requirement demands a different order, and the change would
churn observable output for no behavioural gain — whereas here the breakage is the
**point**: the controller has ruled that those three specifications are invalid, so
tests asserting their acceptance are now asserting the wrong contract. Breaking a
test to implement a ruling is required; breaking one to reshuffle an order nothing
asked to change is not.

**`_reference_scope`'s precedence becomes unreachable, and is deliberately kept.**
Once collisions are rejected, no name can be claimed by two namespaces, so the
`scope.update(SOURCE_BAR_FIELDS)` overwrite can never overwrite anything. This
ruling forbids altering precedence as a substitute for rejection, and the precedence
is retained as defence in depth: it keeps the resolver total if a future version
ever admits a controlled overlap. Its docstring must record that the ordering is now
unreachable rather than continue to claim that "nothing forbids the three namespaces
from colliding", which this ruling makes false.

**Ownership of the implementation.** This correction is a **standalone
controller-directed corrective landing** between the Task 4 implementation commit
`2b8601fb3db4d43691586fd5253cb3473d5248a0` and Task 5. It is **not** owned by any
numbered task in section 9: Task 4 is already committed and Task 5 is versioning
and hashing. Accordingly, Task 4's own restriction — that it "must not modify
Task 3's `validate_strategy_expressions` unless a focused regression proves that its
own implementation independently violates the 256-diagnostic contract", citing
section 5.4.1's scope paragraph — is neither breached nor relied upon here; that
restriction bound Task 4, and this landing is not Task 4. See the cross-reference
note in the Task 4 section.

**Ownership.** The Task 3 static-validation layer owns this check, because it
already holds the parameter names, the feature names, the source-field vocabulary,
and the reference semantics. Task 4's modules change only if a focused test proves
the public entry point can otherwise bypass corrected static validation. No new
source module, no expression-AST change, and no schema field is authorized, and
reference precedence must not be altered as a substitute for rejecting the
ambiguity.

## 6. Exact Stage 4 file map

### 6.1 New source files

| Path | Responsibility |
|---|---|
| `src/crypto_lab/domain/results.py` | `Result[T]` discriminated success-or-diagnostics value, `Success`, `Failure`, helpers |
| `src/crypto_lab/domain/capability_names.py` | `CapabilityName`, `VocabularyVersion` relocated from `adapters/descriptors.py`. **Task 2**, because `StrategySpec` needs them |
| `src/crypto_lab/domain/capability_requirements.py` | `CapabilityRequirement` and `ApproximationPolicy`, per section 5.7 item 6. **Task 2**, because `StrategySpec.required_capabilities` needs them; `capabilities/models.py` re-exports |
| `src/crypto_lab/domain/descriptors.py` | `EngineDescriptor`, `AdapterDescriptor`, `SupportedSchemaVersion`, `OperatingSystem` relocated from `adapters/descriptors.py`, plus a locally defined `BoundedText` and the two `json_schema_extra` hooks per Appendix E; new `RuntimeAvailabilityObservation` |
| `src/crypto_lab/domain/comparison_levels.py` | `ComparisonLevel`, kept in `domain` so Stage 6's `EngineRunRequest` never needs an `adapters -> capabilities` edge. **Task 2**, because `StrategySpec.comparison_requirements` needs it |
| `src/crypto_lab/strategy/yaml_source.py` | Safe YAML loading and the single-pass bounded event-to-value builder of sections 5.2 and 5.3; no node graph is ever composed |
| `src/crypto_lab/strategy/expressions.py` | Closed discriminated expression AST. **Task 2**, because `StrategySpec.entry_rules` and `exit_rules` need it; Task 3 consumes it and must not change a node's field shape |
| `src/crypto_lab/strategy/models.py` | `StrategySpec` and every sub-model |
| `src/crypto_lab/strategy/feature_graph.py` | DAG validation, cycle diagnostics, stable topological order |
| `src/crypto_lab/strategy/validation.py` | Static expression type checking and reference validation |
| `src/crypto_lab/strategy/evaluation.py` | Deterministic Level 1 reference evaluator |
| `src/crypto_lab/strategy/versioning.py` | `StrategyVersion`, `StrategySourceProvenance`, and strategy hashing. `EngineExtensionDeclaration` lives in `strategy/models.py`, because `StrategySpec.engine_extensions` needs it in Task 2 |
| `src/crypto_lab/strategy/loader.py` | `StrategyLoader` facade returning `Result[StrategyVersion]` |
| `src/crypto_lab/capabilities/vocabulary.py` | `capabilities/v1` closed vocabulary |
| `src/crypto_lab/capabilities/models.py` | `CapabilityDeclaration`, `ApproximationDeclaration`, `CompatibilityResult`, and an explicit `__all__` re-exporting `CapabilityRequirement` and `ApproximationPolicy` from `domain`. The `__all__` is mandatory, not cosmetic: mypy `--strict` implies `--no-implicit-reexport`, so Appendix F's `from crypto_lab.capabilities.models import CapabilityRequirement` fails `mypy-all` without it, exactly as Appendix E requires for `adapters/descriptors.py`. `RuntimeAvailabilityObservation` lives in `domain/descriptors.py` |
| `src/crypto_lab/capabilities/policy.py` | `CompatibilityPolicy` and core safety policy |
| `src/crypto_lab/capabilities/resolver.py` | Pure deterministic compatibility resolver |
| `src/crypto_lab/capabilities/comparison.py` | Comparison levels, eligibility contracts, difference classification |

### 6.2 Modified source files

| Path | Change |
|---|---|
| `src/crypto_lab/domain/hashing.py` | Add `DIAGNOSTIC_IDENTITY_V1` (Task 2) and `STRATEGY_VERSION_V1` (Task 5) to `HashingProfile`, plus the `_uuid4_shaped` helper of section 5.3.3 |
| `src/crypto_lab/domain/identifiers.py` | Add `ApproximationId` (`appx_`) and `AvailabilityObservationId` (`avail_`) |
| `src/crypto_lab/adapters/descriptors.py` | Delete the relocated definitions; import every relocated name from `crypto_lab.domain` and re-export it, so the module's public surface and all existing import sites are unchanged |
| `src/crypto_lab/schema_registry.py` | Add nine `SchemaDefinition` entries |
| `src/crypto_lab/domain/__init__.py` | Re-export the new domain names, in the task that defines each |

`src/crypto_lab/domain/__init__.py` is **not** an empty namespace marker: it
imports from all nine existing domain modules and declares an explicit
41-name `__all__`. Every domain module is re-exported through it, so the five
new ones follow the same convention or the package surface becomes
inconsistent. Add, each in the task that defines it: `Result`, `Success`,
`Failure` (Task 2); `CapabilityName`, `VocabularyVersion`,
`CapabilityRequirement`, `ApproximationPolicy`, `ComparisonLevel` (Task 2); and
`EngineDescriptor`, `AdapterDescriptor`, `SupportedSchemaVersion`,
`OperatingSystem`, `RuntimeAvailabilityObservation`, `BoundedText` (Task 6).
Keep `__all__` sorted, as it is today. `domain/__init__.py` is already in
`_ALLOWED_SOURCE_FILES`, so this changes no count. Tasks 2 and 6 therefore add
it to their Files lists.

### 6.3 New schema files

| Path | `$id` |
|---|---|
| `schemas/strategy/strategy-spec-v1.schema.json` | `urn:crypto-lab:schema:strategy:strategy-spec:1.0.0` |
| `schemas/strategy/strategy-version-v1.schema.json` | `urn:crypto-lab:schema:strategy:strategy-version:1.0.0` |
| `schemas/strategy/expression-v1.schema.json` | `urn:crypto-lab:schema:strategy:expression:1.0.0` |
| `schemas/capabilities/capability-requirement-v1.schema.json` | `urn:crypto-lab:schema:capabilities:capability-requirement:1.0.0` |
| `schemas/capabilities/capability-declaration-v1.schema.json` | `urn:crypto-lab:schema:capabilities:capability-declaration:1.0.0` |
| `schemas/capabilities/approximation-declaration-v1.schema.json` | `urn:crypto-lab:schema:capabilities:approximation-declaration:1.0.0` |
| `schemas/capabilities/compatibility-result-v1.schema.json` | `urn:crypto-lab:schema:capabilities:compatibility-result:1.0.0` |
| `schemas/capabilities/runtime-availability-observation-v1.schema.json` | `urn:crypto-lab:schema:capabilities:runtime-availability-observation:1.0.0` |
| `schemas/capabilities/comparison-eligibility-result-v1.schema.json` | `urn:crypto-lab:schema:capabilities:comparison-eligibility-result:1.0.0` |

`RuntimeAvailabilityObservation` sits under `schemas/capabilities/` even though
its model lives in `crypto_lab/domain/descriptors.py` beside
`AdapterDescriptor`, whose schema is under `schemas/protocol/`. That is
deliberate: the schema directory reflects the **owning stage's permission**,
and Stage 4 holds the capability-schema permission while `schemas/protocol/` is
frozen Stage 3 output that Stage 4 must leave byte-identical. Stage 6 must not
relocate it, because moving a generated file would break the byte-identity
proof of section 10.

`RuntimeAvailabilityObservation` is included deliberately. Specification
section 11.3 lists it as a required record and section 33.2 requires every
section 11 record to have a generated versioned JSON Schema. Stage 4 defines
the model because section 8.2 puts it in `resolve()`, and Stage 4 holds the
capability-schema permission, so deferring the schema would orphan a mandatory
acceptance artifact in a stage whose permission does not clearly cover it.
Nine schemas are added in total.

### 6.4 New test files

| Path | Coverage |
|---|---|
| `tests/unit/strategy/test_strategy_yaml_source.py` | Loader contract, the section 5.2.1 event classifier including the `event.tag is None` premise, the section 5.2.2 mapping-key contract, the section 5.2.3 `SourceName` pattern, tags, duplicate keys, merge keys, documents, encoding |
| `tests/unit/strategy/test_strategy_yaml_bounds.py` | Every builder bound in section 5.3, including alias expansion, and excluding `MAX_EXPRESSION_DEPTH`, which section 5.3 marks post-parse |
| `tests/unit/strategy/test_strategy_expressions.py` | Every AST node, arity, discriminator closure, model-level `bars_ago` and depth bounds; owned by Task 2 |
| `tests/unit/strategy/test_strategy_models.py` | `StrategySpec` fields, unknown-field rejection, policy limits |
| `tests/unit/strategy/test_strategy_validation.py` | Static type checking and reference validation |
| `tests/unit/strategy/test_strategy_feature_graph.py` | DAG validation, cycle diagnostics, topological order |
| `tests/unit/strategy/test_strategy_evaluation.py` | Warm-up, missing values, Decimal, divide-by-zero, crossovers |
| `tests/unit/strategy/test_strategy_versioning.py` | Hash inclusion and exclusion, extension hashes |
| `tests/unit/strategy/test_strategy_loader.py` | End-to-end `Result[StrategyVersion]` |
| `tests/unit/capabilities/test_capability_vocabulary.py` | Closed vocabulary membership and versioning |
| `tests/unit/capabilities/test_capability_models.py` | Requirement, declaration, approximation validation |
| `tests/unit/capabilities/test_capability_policy.py` | `runtime.live` and every forbidden request |
| `tests/unit/capabilities/test_capability_resolver.py` | All four outcomes, ordered complete reasons |
| `tests/unit/capabilities/test_capability_comparison.py` | Levels, eligibility, difference classification |
| `tests/unit/domain/test_domain_results.py` | `Result` discrimination |
| `tests/unit/domain/test_domain_capability_contracts.py` | `CapabilityName`, `VocabularyVersion`, `CapabilityRequirement`, `ApproximationPolicy`, `ComparisonLevel` — the Task 2 domain contracts `StrategySpec` depends on |
| `tests/unit/domain/test_domain_descriptors.py` | Relocated descriptors and `RuntimeAvailabilityObservation`; owned by Task 6 |
| `tests/property/test_strategy_hashing.py` | Formatting independence, material sensitivity |
| `tests/property/test_compatibility_resolution.py` | Order-independence, reason stability |
| `tests/property/test_expression_evaluation.py` | Decimal and missing-value invariants |
| `tests/safety/test_stage4_boundaries.py` | Forbidden YAML API names by qualified, bare, and import-form matching; typing integrity; the guard's own negative and positive fixtures. **Must not import `yaml`** |
| `tests/safety/test_stage4_yaml_runtime.py` | The absolute `yaml.SafeLoader.yaml_constructors` pin, the `StrictStrategySafeLoader.__dict__` and `__mro__` assertions, and the yaml-import-closure check. Imports `yaml` |
| `tests/architecture/test_package_import_boundaries.py` | `strategy` and `capabilities` dependency direction |

**Every test module basename must be globally unique.** `tests/` contains no
`__init__.py`, and neither `pyproject.toml` nor `conftest.py` sets
`--import-mode`, so pytest's default `prepend` mode imports each test module by
bare basename and aborts collection with `import file mismatch` on a duplicate.
The merged repository already maintains this invariant: every existing test
basename is unique, and `tests/unit/datasets/test_dataset_models.py` carries
its prefix for exactly this reason. Unprefixed `test_models.py`,
`test_versioning.py`, and `test_loader.py` would each collide with an existing
module, and Appendix A forbids the `pyproject.toml` change that would otherwise
allow `importmode=importlib`.

### 6.5 New fixtures

`tests/fixtures/strategy/` holds small deterministic non-secret inputs and
expected outputs, all UTF-8 with LF endings:

```text
sma_cross_long.valid.yaml                 golden/sma_cross_long.features.json
sma_cross_long.reordered_keys.yaml        golden/sma_cross_long.signals.json
sma_cross_long.commented.yaml             golden/warm_up_boundary.features.json
warm_up_boundary.valid.yaml               golden/crossover_equality.signals.json
crossover_equality.valid.yaml             golden/missing_input.features.json
missing_input.valid.yaml                  golden/bar_offsets.features.json
bar_offsets.valid.yaml                    golden/decimal_rounding.features.json
decimal_rounding.valid.yaml               golden/adjacent_entry_exit.signals.json
adjacent_entry_exit.valid.yaml
invalid/python_tag.yaml                   invalid/unknown_tag.yaml
invalid/duplicate_key.yaml                invalid/merge_key.yaml
invalid/two_documents.yaml                invalid/billion_laughs.yaml
invalid/deep_nesting.yaml                 invalid/recursive_alias.yaml
invalid/feature_cycle.yaml
```

This inventory is the **exact** set of expected-created fixture files. It is the
list a reviewer compares against the filesystem, so it names no file that no
task creates. Three `invalid/` names an earlier draft listed here have been
removed from it and carry recorded non-created dispositions in the table below.

#### 6.5.1 `invalid/` fixture disposition table — reviewed correction

The eight `invalid/` files Task 2 shipped at `9a2c73f` need no entry: they exist
and their tests pass. This table closes the four names that had **no** creating
task, which was a plan defect rather than an implementation defect. Removing a
name from the inventory removes **only the file**; every behavioural test the
plan requires for that condition is preserved and named below.

| # | Fixture path | Disposition | Behaviour that remains mandatory |
|---|---|---|---|
| 1 | `invalid/feature_cycle.yaml` | **`CREATED_BY_TASK_4`** | Task 4 step 2. Added to Task 4's Files list by this correction; the only new fixture path authorized |
| 2 | `invalid/future_reference.yaml` | **`NOT_CREATED_UNREACHABLE_IN_EXPRESSIONS_V1`** | `STRATEGY.REFERENCE_FUTURE_BAR` remains reserved in the section 5.9 closed table. No dead branch and no misleading fixture is added. See section 6.5.2 |
| 3 | `invalid/unknown_operation.yaml` | **`NOT_CREATED_DIRECT_TASK2_TASK3_TEST_COVERAGE`** | **Expression-level** closed-union rejection of an unknown `op` remains **mandatory**, covered directly by Task 2's `tests/unit/strategy/test_strategy_expressions.py` discriminator-closure tests and by Task 3's dispatch-table closure test. A YAML fixture cannot test it better: the discriminated union rejects an unknown `op` at model construction, which is upstream of any fixture. The **feature-level** case is a separate obligation — see the note below |
| 4 | `invalid/type_mismatch.yaml` | **`NOT_CREATED_DIRECT_TASK3_TEST_COVERAGE`** | **Expression-level** static type rejection remains **mandatory**, covered directly by Task 3 step 2's three named cases — boolean operand to `add`, decimal operand to `and`, string compared to integer — as in-module trees rather than a file. The **feature-level** case is a separate obligation — see the note below |

Entries 3 and 4 follow section 6.5.4's own existing rule: a case whose expected
error code *is* the whole assertion is authored in the test module, and only
multi-line adversarial documents and the valid golden inputs are fixture files.
Neither disposition weakens a validation rule, and neither removes a test.

**Both fixture names were ambiguous between two levels, and the feature level is
discharged separately, not dropped.** `unknown_operation` matches both
`STRATEGY.EXPRESSION_UNKNOWN_OP` and `STRATEGY.FEATURE_UNKNOWN_OPERATION`;
`type_mismatch` matches both `STRATEGY.EXPRESSION_TYPE_MISMATCH` on an expression
operand and the same code on a feature **input**. Rows 3 and 4 discharge the
expression level only. The feature level is a **rank-1 normative requirement** —
specification section 12.3.1 line 701 states that "A feature graph must be
acyclic, every input must exist and type-check, and declared warm-up must be at
least the maximum dependency warm-up", and the feature-operation allowlist is
Task 4's — so it is discharged by three **named Task 4 tests**, added to Task 4's
test requirements by this correction rather than left to a removed fixture:

1. a `FeatureDefinition.operation` outside Task 4's closed feature-operation
   allowlist yields `STRATEGY.FEATURE_UNKNOWN_OPERATION`;
2. a feature `input` naming neither a permitted bar field nor a declared feature
   yields `STRATEGY.REFERENCE_UNKNOWN`;
3. a feature `input` or `parameter` whose declared type does not satisfy its
   operation's typed signature yields `STRATEGY.EXPRESSION_TYPE_MISMATCH`.

No new error code is required for any of the three: all are already in the
section 5.9 closed table. This closes what would otherwise have been a real
coverage hole — before this correction, `STRATEGY.FEATURE_UNKNOWN_OPERATION`
appeared nowhere in `src/` or `tests/`, and `FeatureDefinition.operation` is
pattern-validated only, so an operation such as `bogus.thing/v1` constructs
cleanly today.

#### 6.5.2 `future_reference` — the recorded `strategy/v1` disposition

Task 3's test-first step 4 (this document, Task 3 step 4) reads
"`invalid/future_reference.yaml` is rejected with
`STRATEGY.REFERENCE_FUTURE_BAR`". That step is **resolved, not outstanding**, by
a recorded execution ruling, and this subsection is its authoritative home so
the two statements cannot be read as a live contradiction:

1. `RefExpression.bars_ago` is non-negative by model contract, and
   specification line 699 makes `bars_ago = 0` the current **fully closed** bar
   and `bars_ago > 0` an earlier closed bar. A non-negative offset therefore
   names a current or historical closed bar only.
2. A negative `bars_ago` is rejected at `StrategySpec` construction with
   `STRATEGY.REFERENCE_NEGATIVE_OFFSET`, before static validation and before any
   evaluation.
3. Within `expressions/v1` there is consequently **no representable expression
   that names a future or still-open bar**. The condition is unrepresentable, not
   merely untested.
4. Task 4 therefore adds no `future_reference` fixture, no
   `STRATEGY.REFERENCE_FUTURE_BAR` evaluator branch, and no negative-offset
   workaround. Task 4's own evaluator API takes an explicit bounded in-memory bar
   series and cannot observe an attempted future read either, so Task 4 records
   this finding rather than adding dead code.
5. `STRATEGY.REFERENCE_FUTURE_BAR` **remains reserved** in the section 5.9 closed
   table for a future expression-semantics version whose grammar can represent
   the condition. It is not removed, and removing it is not authorized.
6. **The rank-1 coverage requirement is cited and discharged, not dissolved.**
   Specification section **12.3.3 line 713** states: "Golden examples cover
   first-valid warm-up bar, crossover equality boundaries, missing inputs,
   explicit bar offsets, Decimal rounding, entry and exit on adjacent bars, and
   invalid future references." That sentence is the normative origin of all seven
   golden scenarios: six became the root `*.valid.yaml` inputs of section 6.5.3,
   and the seventh is this one. Until this correction the plan had never cited
   section 12.3.3 at all, and citing only line 699 — which is the **prohibition**,
   not the **coverage requirement** — would let a rank-6 document quietly close a
   rank-1 item. It is therefore discharged explicitly, in-module rather than by a
   fixture file, by these **committed** tests:
   - `tests/unit/strategy/test_strategy_expressions.py::test_a_negative_offset_is_rejected_with_the_negative_offset_code`
   - `tests/unit/strategy/test_strategy_validation.py::test_a_negative_offset_is_rejected_by_its_own_exact_diagnostic`
   - `tests/unit/strategy/test_strategy_validation.py::test_no_accepted_reference_model_can_carry_a_negative_offset`
   - `tests/unit/strategy/test_strategy_validation.py::test_every_accepted_reference_in_a_validated_specification_is_historical`
   - `tests/unit/strategy/test_strategy_validation.py::test_the_module_emits_exactly_its_own_three_error_codes`

   The emitted code is `STRATEGY.REFERENCE_NEGATIVE_OFFSET`, because that is the
   only way `expressions/v1` can express the invalid-future-reference condition at
   all. No fixture file is added, because a fixture would have to encode an
   expression the grammar cannot represent. This is a "covered elsewhere, and
   better" discharge — the same class of argument section 6.5.1 rows 3 and 4 use —
   not a claim that no coverage is owed. Should a controller prefer a fixture
   instead, that requires a fresh human ruling; a plan amendment alone cannot
   grant it.

#### 6.5.3 Fixture roles, ownership, and golden pairings — reviewed correction

**Two roles, never mixed.** Root-level `*.valid.yaml` files are complete
`StrategySpec` **input** documents. `tests/fixtures/strategy/golden/**` holds
expected evaluator **output** JSON and nothing else. `golden/**` is output-only;
no input document may be placed beneath it.

**Ownership.**

| Fixture set | Owning task |
|---|---|
| `sma_cross_long.{valid,reordered_keys,commented}.yaml` | Task 2 (committed at `9a2c73f`); Task 4 **consumes** them |
| the eight `invalid/` files Task 2 shipped | Task 2 (committed at `9a2c73f`) |
| `invalid/feature_cycle.yaml` | **Task 4** |
| the six root `*.valid.yaml` golden inputs below | **Task 4** |
| `golden/**` expected-output JSON | **Task 4** |

**Exact input-to-golden pairings.** Each input has exactly one defined pairing:

```text
warm_up_boundary.valid.yaml      -> golden/warm_up_boundary.features.json
crossover_equality.valid.yaml    -> golden/crossover_equality.signals.json
missing_input.valid.yaml         -> golden/missing_input.features.json
bar_offsets.valid.yaml           -> golden/bar_offsets.features.json
decimal_rounding.valid.yaml      -> golden/decimal_rounding.features.json
adjacent_entry_exit.valid.yaml   -> golden/adjacent_entry_exit.signals.json
sma_cross_long.valid.yaml        -> golden/sma_cross_long.features.json
                                 -> golden/sma_cross_long.signals.json
```

**Construction rules.** Every new YAML input must: be a complete valid
`StrategySpec` document; pass the safe YAML loader; pass strict `StrategySpec`
construction; pass Task 3 static expression validation; pass feature-reference
validation apart from the behaviour intentionally under test; use only existing
Stage 4 operations and types; remain spot-only, long-only, no-leverage, and
non-live; be UTF-8 without BOM; use LF line endings; contain no path, credential,
network, environment, or engine-specific material; supply its own basename as the
non-path `SourceName` given to the loader; and isolate its named behaviour with
the smallest reviewable strategy.

**Scenario intent must stay distinct** — these are not aliases of one strategy:

| Fixture | Isolates |
|---|---|
| `warm_up_boundary` | the exact first bar on which a feature becomes available after warm-up |
| `crossover_equality` | the **equality edge** of the approved crossover definition, not merely another ordinary crossing |
| `missing_input` | the approved missing-value behaviour, with no unrelated type, reference, or cycle failure |
| `bar_offsets` | current-bar and permitted historical offsets. Its golden is a **features** file, so the offset mechanism under test is the feature-level `shift/v1` operation, not `RefExpression.bars_ago`. It must **not** attempt to encode an unrepresentable future reference (section 6.5.2) |
| `decimal_rounding` | exact `Decimal` semantics; a Python `float` is never the expected-value authority |
| `adjacent_entry_exit` | the approved behaviour when entry and exit signals occur on **adjacent** bars |

No economic semantics beyond the approved plan may be invented.

**Two committed constraints an author will otherwise trip.** Both are recorded
here because they are invisible from the fixture's own text:

1. **Negative zero is forbidden at the canonical boundary.** `format_decimal` in
   `crypto_lab/domain/financial.py` raises `ValueError("negative zero is
   forbidden")`, so a `Decimal("-0")` intermediate — which `negate` of zero and
   `multiply` by zero both produce — would raise out of canonical serialization
   and out of the `Result`-only contract. The evaluator must normalize a zero
   result to unsigned zero before it reaches serialization, and
   `decimal_rounding` must cover that case.
2. **Timestamps cannot be ordered.** Task 3 types `bar.timestamp_utc` as `STRING`
   and narrows `ORDERING` to numeric operands, so only `equal` and `not_equal`
   accept a timestamp. A fixture that compares timestamps with a relational
   operator earns `STRATEGY.EXPRESSION_TYPE_MISMATCH` and fails its own
   construction rule that it must pass Task 3 static validation.

**Golden outputs are review oracles, not evaluator transcripts.** This restates
and sharpens section 7's existing rule. An expected JSON file must **not** be
created by running the production evaluator and copying its output. Each expected
complete series is derived independently from the input bars, the feature
definitions, declared warm-up, the missing-value policy, exact `Decimal`
arithmetic, the crossover rules, and the entry and exit expressions. Tests may
compare evaluator output against the reviewed JSON, but the implementation under
test must never be the source used to author it. Each expected series is reviewed
by hand, or by a separate test-only calculation whose logic does not call the
production evaluator, **before** implementation.

**TDD disposition.** Fixture files and expected JSON are test data, so they may be
authored together with their focused tests before production implementation.
"Fixture missing" is **not** an acceptable meaningful RED. The required RED must
demonstrate missing or incorrect feature-graph or evaluation behaviour **after**
the input YAML loads successfully, `StrategySpec` validates, and Task 3 static
validation succeeds — so each scenario must be shown to reach the Task 4
evaluator boundary.

#### 6.5.4 Hash-equivalent triple and inline-literal cases

These two paragraphs are pre-existing section 6.5 body text. Subsections 6.5.1 to
6.5.3 were inserted above them and they were given this heading, so that the
`future_reference` disposition does not appear to own them. Their wording is
**unchanged** — the diff shows no deletion in this region, which is the proof.

`sma_cross_long.valid.yaml`, `sma_cross_long.reordered_keys.yaml`, and
`sma_cross_long.commented.yaml` differ only in comments, whitespace, and
mapping key order, and must produce an identical `content_hash`.

The single-line classifier cases of section 5.2.1, the key-shape cases of
section 5.2.2, and the `SourceName` cases of section 5.2.3 are authored as
inline `bytes` literals in the test module, not as fixture files. Each is one
or two lines, the expected error code is the whole assertion, and forty
near-identical files would obscure rather than document the contract. Only
multi-line adversarial documents — the nested alias bomb, deep nesting,
recursive alias, feature cycle, and the valid golden inputs — are fixture files.

### 6.6 Modified test and documentation files

| Path | Change |
|---|---|
| `tests/safety/test_stage3_boundaries.py` | **Tasks 2 through 8**, each applying only the subset matching the files and deferred names it creates: `_ALLOWED_SOURCE_FILES`, `_ALLOWED_IMPORT_ROOTS`, `_DEFERRED_DEFINITIONS`, schema count `11` to `20`. Task 9: the Stage 4 completion status guard only |
| `tests/safety/test_project_dependencies.py` | `_EXPECTED_RUNTIME_REQUIREMENTS`, `_EXPECTED_DEVELOPMENT_NAMES`, pinned mypy table keys |
| `tests/unit/test_schema_registry.py` | Closed 11-entry `_EXPECTED` path-to-`$id` map, `len(SCHEMA_DEFINITIONS) == 11`, and the test name (Appendix I) |
| `tests/unit/test_package_layout.py` | Closed `PACKAGE_MODULES` list, which drives the fresh-import probe |
| `pyproject.toml` | Add `pyyaml>=6.0.3,<7`; add `types-pyyaml>=6.0.12,<7` to `dev` |
| `uv.lock` | Regenerated by the launcher; never hand-edited |
| `docs/development/verification.md` | Stage 4 focused checks and schema count |
| `README.md` | Status line and strategy-loading summary |
| `docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md` | **Task 9 only.** Stage 4 implementation complete at the Task 8 commit, Task 9 status finalization distinguished from the implementation hash, Stage 5 still not started |

Stage 4 implementation must not modify the corrected launcher
`scripts/invoke-uv.ps1` at `350fac49ff5b1db4ec62b60c7ade76580f9894dd`, nor
`scripts/verify.ps1`, `scripts/generate_schemas.py`,
`scripts/verify_schema_distribution.py`, or
`tests/safety/test_uv_launcher.py`. This prohibition is anchored to the
corrected launcher, not to the pre-correction behaviour that section 3.8
replaced: the bootstrap deadlock was repaired before Stage 4 began, and Stage 4
neither needs nor is permitted to touch it again.

## 7. TDD policy

Every production behaviour follows the same cycle, and every task in section 9
states its own instance of it:

1. Write one focused failing test that names the exact behaviour.
2. Run the focused test through `pytest-focused` and record the **expected RED**
   message, not merely a non-zero exit.
3. Write the minimum implementation that makes it pass.
4. Run the focused test again and record GREEN.
5. Run the broader package suite.
6. Run `ruff-format-all`, `ruff-check-all`, and `mypy-all`.
7. Run `schema-generate-check` when the task touches models in the registry.
8. Perform the task's security review against section 5.
9. Obtain the task's independent review.
10. Commit with the exact message, leaving the worktree clean.

Focused runs use the coverage override, which the launcher permits only as the
exact leading pair `-o addopts=`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\strategy -q
```

The final suite must satisfy the configured 90 percent branch-coverage gate
without the override. Stage 4 must not lower `--cov-fail-under`, and the
merged-main branch coverage must not fall below the Stage 3 baseline of
93.64 percent by more than one percentage point; a larger drop requires added
tests, not a lowered gate.

**The gate applies at every task boundary, not only at the end of the stage.**
`--cov-fail-under=90` and `--cov-branch` live in
`[tool.pytest.ini_options].addopts`, so the `pytest-all` profile enforces them
repository-wide, and every task from Task 2 onward runs `pytest-all` and must
end clean. Each task therefore carries enough tests to cover the code it lands
in the same commit. A task that adds a large module — the evaluator, the
resolver, the bounded event scanner — cannot defer its coverage to a later
task, and must not reach for the `-o addopts=` override outside a focused
diagnostic run.

Fixtures are data, not behaviour. A golden fixture is written **after** the
evaluator produces a value that has been reviewed by hand against
specification section 12.3, never by pasting the evaluator's first output.

## 8. Offline-first dependency acquisition

Stage 4 introduces `pyyaml` and `types-pyyaml`. Task 1 performs, in this exact
order:

```powershell
# 1. Offline lock resolution after the approved pyproject.toml edit
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 lock-resolve-offline

# 2. Offline lock check
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 lock-check

# 3. Offline synchronization
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 sync
```

If and only if step 1 fails because required registry **metadata** is absent
locally, stop, present this exact command, and run it only after separate
explicit one-time user approval:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 lock-acquire
```

If and only if step 3 fails because locked **distributions** are absent
locally, stop, present this exact command, and run it only after separate
explicit one-time user approval:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 sync-acquire
```

After either acquisition, immediately return to steps 2 and 3 in their offline
form and record their results. Neither acquisition command may be embedded in
a script, a loop, or an automatically executed sequence. Acquisition is
bootstrap evidence, never verification evidence, and no verification gate may
cite it. `pyproject.toml` and the regenerated `uv.lock` are committed together
in Task 1.

`test_lock_registry_artifacts_are_sha256_pinned` already requires every locked
artifact to carry a `sha256:` digest and to come from
`https://pypi.org/simple`; the new packages inherit that requirement without a
test change.

## 9. Task decomposition

Nine separately reviewable tasks. No task may be merged into another, and each
ends in a clean committed worktree. Task 8 owns the complete implementation
acceptance and the implementation commit; Task 9 owns only the Stage 4
completion status and its executable guard, because a task cannot write its own
commit hash into the roadmap.

**Closed-world guard rule.** `tests/safety/test_stage3_boundaries.py` is in the
Files list of **every** task from Task 2 onward, and each task applies only the
subset of Appendix C matching the files and deferred names it actually creates.
This is mandatory because `test_stage3_source_file_set_is_closed` asserts exact
set equality against the real filesystem: a task that adds a source file
without extending `_ALLOWED_SOURCE_FILES` fails, and a task that adds the whole
Appendix C list up front also fails, because the allowlist would then name
files that do not yet exist. `_DEFERRED_DEFINITIONS` removals follow the same
rule — remove a name in the task that defines it, never earlier.
`_ALLOWED_IMPORT_ROOTS` is membership-only, so its four additions may be made
once in Task 2.

### 9.0 Implementation preflight

Run this preflight once, before Task 1. Every step must pass. Stop and report
on the first failure; do not begin Task 1 with a failing baseline.

1. **Verify clean local `main`, and prove the prerequisites by ancestry.**
   From the main checkout:

```powershell
git -C "C:\Users\59557\Documents\Projects\Crypto_Trading" status --short
git -C "C:\Users\59557\Documents\Projects\Crypto_Trading" branch --show-current
git -C "C:\Users\59557\Documents\Projects\Crypto_Trading" merge-base `
  --is-ancestor 350fac49ff5b1db4ec62b60c7ade76580f9894dd HEAD
```

   Status must be empty and the branch must be `main`.
   `merge-base --is-ancestor` prints nothing on success **or** failure and
   PowerShell does not surface a native non-zero exit, so read `$LASTEXITCODE`
   explicitly — otherwise both outcomes look identical:

```powershell
if ($LASTEXITCODE -ne 0) { throw "launcher bootstrap prerequisite is absent" }
```

   Comparing `git rev-parse HEAD` to a hash proves nothing about containment,
   which is why the ancestry test is the gate: it is the only check that
   actually establishes the launcher bootstrap correction is present. Repeat
   both the `merge-base --is-ancestor` call and the `$LASTEXITCODE` check for
   the **corrected-plan approval commit**, which the separate
   roadmap-and-guard commit recorded in the Stage 4 row of roadmap section 9
   together with the executable plan-approval guard. That row also still names
   the earlier pre-correction review commit `bf5e427a8fe0…`; the approval
   commit is the one the row labels "corrected detailed plan approved at", and
   the plan-approval guard pins it by name, so read the hash from the guard
   constant rather than by eye. If either check is non-zero, stop: Stage 4 has
   no approved base, and preflight step 5 would reproduce the fresh-worktree
   deadlock.

2. **Create the external branch and worktree.** Stage 4 is implemented outside
   the main checkout:

```powershell
git -C "C:\Users\59557\Documents\Projects\Crypto_Trading" worktree add `
  -b project-1-stage-4-implementation `
  "C:\Users\59557\Documents\Projects\Crypto_Trading-worktrees\project-1-stage-4-implementation" `
  main
```

3. **Verify `HEAD`, `main`, and the merge base.** From the new worktree, these
   three must be the same commit:

```powershell
git rev-parse HEAD
git rev-parse main
git merge-base HEAD main
```

   `git status --short` must be empty.

4. **Initialize the ignored SDD ledger** at
   `.superpowers/sdd/<date>-project-1-stage-4-implementation/`, following the
   Stage 3 precedent. `.gitignore` already ignores `/.superpowers/sdd/`, so the
   ledger never enters a commit. It records each task's expected RED, measured
   GREEN, verification logs, review findings, and their resolutions.

5. **Create the worktree environment with the launcher `sync` profile, before
   any Python-bearing profile.** A new worktree has no `.venv`, and `sync` is
   the operation that creates it:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 sync
```

   This is the corrected bootstrap profile of section 3.8. It runs offline. No
   direct `uv` command is authorized, and no Python-bearing profile —
   including `pytest-focused`, `mypy-all`, `ruff-check-all`, and `build` — can
   run before it succeeds.

6. **Run the complete inherited verifier** and require a first-attempt pass:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

7. **Begin Task 1 only after that baseline passes.** Record the baseline result
   in the ledger. A failing baseline is a blocked stage, not a Task 1 RED.

### 9.1 Cross-task ownership notes

These are section-9 ownership rules, not preflight steps. Tasks 3 and 5 cite
them as "the reason given in section 9". Task 7 does not: it resolves
`ComparisonLevel` through section 5.7 item 6 instead.

**Task 2 additionally owns `strategy/expressions.py`.** `StrategySpec` declares
`entry_rules` and `exit_rules` as expression trees, so the model cannot be
defined without the AST, and the source-file guard forbids Task 2 from creating
a file Task 3 owns. Task 2 therefore defines the closed AST node models **and
owns their per-node tests** in
`tests/unit/strategy/test_strategy_expressions.py`, because a task must carry
the tests covering the code it lands in the same commit. Task 3 owns
`validation.py`, the static type and reference checking, and
`tests/unit/strategy/test_strategy_validation.py` only.

**Task 2 also owns `EngineExtensionDeclaration`, in `strategy/models.py`, with
exactly these seven fields** from specification section 12.6: `adapter_name`,
`extension_id`, `version`, `content_hash`, `purpose`, `lifecycle_effect`, and
`economic_effect`. The first three are the section 5.5 item 5 sort key for
`extension_hashes`, so a naming divergence here propagates straight into a
permanent `content_hash`; they are fixed at Task 2 and Task 5 may not rename
them. `engine_extensions` is one of the twenty-one
`StrategySpec` fields, and specification section 12.6 fixes its seven
sub-fields, so the model cannot be defined without the declaration type — the
same forward-dependency shape as the AST above. Task 5 must not own it: Task 5
owns `strategy/versioning.py`, which the source-file guard forbids Task 2 from
creating. Task 5 therefore **consumes** `EngineExtensionDeclaration` and
produces only `StrategySourceProvenance`, `StrategyVersion`,
`strategy_version_hash`, and `StrategyLoader`. Section 5.5 item 5 hashes the
declared extension `content_hash` values, which are fields of the Task 2 type.

### Task 1 — YAML dependency, lock gates, and security tests

**Files:** `pyproject.toml`, `uv.lock`, `tests/safety/test_project_dependencies.py`,
`tests/safety/test_stage4_boundaries.py` (new, must not import `yaml`),
`tests/safety/test_stage4_yaml_runtime.py` (new, imports `yaml`).

**Consumes:** the Stage 3 launcher profiles and dependency guards.
**Produces:** an installed, locked, typed `yaml` import root and the Stage 4
source-level security guard.

**RED classification.** A test file this task itself creates is never "missing"
in a meaningful sense, and collection failure is not behavioural RED. Task 1's
tests fall into two classes, and the ledger must record them separately.

*Meaningful RED — three assertions that fail against real repository state and
go green only when this task changes that state, in this order:*

1. **Dependency-policy assertion fails before the `pyproject.toml` change.**
   With `_EXPECTED_RUNTIME_REQUIREMENTS` and `_EXPECTED_DEVELOPMENT_NAMES`
   updated to include `pyyaml>=6.0.3,<7` and `types-pyyaml`,
   `test_project_runtime_dependencies_are_exact` and
   `test_required_development_tools_are_declared` fail against the unmodified
   `pyproject.toml`. Record the exact `AssertionError` comparing the current
   one-element runtime tuple and the current seven-name development set.
2. **Lock assertion fails before lock regeneration.** The new lock test — that
   `uv.lock` contains a `types-pyyaml` package, and that the locked `pyyaml`
   package has a `wheels` entry matching `cp312` and `win_amd64` — fails
   against the unmodified `uv.lock`. Record the failure before running the
   section 8 flow.
3. **`yaml` import availability fails before synchronization.** The absolute
   `SafeLoader` constructor-tag assertion of step 2 below requires
   `import yaml`, which raises `ModuleNotFoundError` until the launcher `sync`
   profile installs PyYAML. Record that as the third RED, and record its GREEN
   only after an offline `sync` succeeds.

*Preventive safety tests — expected to begin GREEN, and explicitly not
fabricated behavioural RED:* the AST forbidden-name guard of step 1, the
typing-integrity guard of step 3, and the mypy-configuration-key guard of step
4. Stage 4 has written no `yaml` usage yet, so these pass the moment they
exist. They are guardrails against a future regression, and the ledger records
them as such. Do not manufacture a temporary violating file to force them red.

**Test-first sequence**

1. Add to `tests/safety/test_stage4_boundaries.py` an AST test over every file
   under `src/crypto_lab`, using **two distinct matching modes**. Mixing them
   is what makes the guard real:

   **Qualified matching**, for names that are dangerous only as members of the
   `yaml` module: `load`, `full_load`, `unsafe_load`, `safe_load`, `compose`,
   `compose_all`. Match an `ast.Attribute` whose `.attr` is one of those **and**
   whose `.value` resolves to the module's binding for `yaml`, reusing the
   `_import_aliases(tree)` helper that `tests/safety/test_stage3_boundaries.py`
   already provides. Bare-name matching is wrong for these two ways round: a
   dotted string such as `"yaml.safe_load"` can never equal an
   `ast.Attribute.attr`, which is `safe_load`, so a literal reading makes the
   guard **vacuous for exactly the six most dangerous names**; and reducing
   them to bare attrs would trip on the plan's own `StrategyLoader.load`
   (section 6.1) and neighbours `tomllib.loads` in
   `crypto_lab/configuration/loader.py`.

   **Import-form matching**, which closes the hole that qualified matching
   alone leaves. `from yaml import safe_load` followed by a bare `safe_load(x)`
   produces no `ast.Attribute` at the call site, so qualified matching cannot
   see it, and the six names are deliberately absent from bare matching. The
   existing import-root test is no backstop: it takes
   `module.partition(".")[0]` and only checks the root, which Appendix C makes
   `yaml` allowed. Therefore also match any `ast.ImportFrom` whose module is
   `yaml` or begins `yaml.` and whose imported names include **any** name from
   either list, and add a fourth negative fixture using that form. Of the six
   qualified names, `full_load`, `unsafe_load`, `safe_load`, `compose`, and
   `compose_all` are additionally added to bare matching — none collides with
   anything in `src/crypto_lab`. Only `load` stays qualified-only, because
   `StrategyLoader.load` is a legitimate Stage 4 method.

   **Bare-name matching**, for names that cannot collide with legitimate code,
   against `ast.Name.id`, `ast.Attribute.attr`, and assignment targets:
   `full_load`, `unsafe_load`, `safe_load`, `compose`, `compose_all`,
   `Loader`, `FullLoader`, `UnsafeLoader`, `CLoader`, `CFullLoader`,
   `CUnsafeLoader`, `CSafeLoader`, `CBaseLoader`, `CParser`, `cyaml`, `_yaml`,
   `YAMLObject`, `add_constructor`, `add_multi_constructor`,
   `add_implicit_resolver`, `yaml_constructors`, `yaml_multi_constructors`,
   `yaml_implicit_resolvers`, plus the redaction attributes of section 5.2
   item 14: `get_snippet`, `buffer`, `problem`, `context`, `note`.
   The three `yaml_*` attribute names matter independently of the `add_*`
   methods, because `StrictStrategySafeLoader.yaml_constructors[t] = f` mutates
   the inherited `yaml.SafeLoader` dict. Never match substrings, and never
   match `ast.keyword.arg`, so the required `Loader=StrictStrategySafeLoader`
   keyword does not self-collide with the banned bare name `Loader`.

   **The guard is itself tested.** A vacuous guard is indistinguishable from a
   passing one, so add negative fixtures parsed from in-test source strings —
   `yaml.safe_load(x)`; `import yaml as y` then `y.compose(x)`; `Loader = 1`;
   and `from yaml import safe_load` then `safe_load(x)` — asserting each is
   detected, plus a positive fixture asserting `obj.load()` and
   `tomllib.loads(x)` are **not** flagged.

   `_import_aliases` is reused from `tests/safety/test_stage3_boundaries.py`.
   `tests/` has no `__init__.py`, so that is a cross-module import resolved
   through pytest's default `prepend` `sys.path` insertion; both modules live
   in `tests/safety/`, so the import is `from test_stage3_boundaries import
   _import_aliases`. If that coupling is judged undesirable at implementation
   time, copy the helper rather than weakening the matching.
   **Preventive safety test; begins GREEN** against `src/crypto_lab`, while its
   own negative fixtures exercise it immediately.
2. Add the **absolute** part of the global-state test that does not depend on
   Stage 4 code: assert
   `frozenset(yaml.SafeLoader.yaml_constructors) == _EXPECTED_SAFELOADER_TAGS`.
   This holds at import time and catches a third-party `yaml.YAMLObject`
   registration. A before/after-load comparison is structurally incapable of
   detecting class-body or import-time mutation, which is why the assertion is
   absolute.

   `_EXPECTED_SAFELOADER_TAGS` is **thirteen** entries: the twelve
   `tag:yaml.org,2002:` tags `null`, `bool`, `int`, `float`, `binary`,
   `timestamp`, `omap`, `pairs`, `set`, `str`, `seq`, `map`, **plus the `None`
   key** that `SafeConstructor.add_constructor(None,
   SafeConstructor.construct_undefined)` registers. Omitting the `None` key is
   the likely first-attempt error, and the resulting failure looks like a
   supply-chain alarm rather than a test bug.

   **This assertion lives in its own module**, `tests/safety/test_stage4_yaml_runtime.py`,
   with a module-level `import yaml`. Steps 1 and 3 stay in
   `tests/safety/test_stage4_boundaries.py`, which must **not** import `yaml`.
   Otherwise a module-level `import yaml` would make the whole file
   uncollectable until synchronization, so the preventive tests declared to
   begin green could not run at all — contradicting this task's own RED
   classification.

   **Meaningful RED 3:** `ModuleNotFoundError: No module named 'yaml'` until
   the launcher `sync` profile installs PyYAML.
   The two assertions that name `StrictStrategySafeLoader` — that
   `"yaml_constructors" not in StrictStrategySafeLoader.__dict__` and that
   `yaml.SafeLoader in StrictStrategySafeLoader.__mro__` — and the
   import-closure test asserting the yaml-importing file set is exactly
   `{"strategy/yaml_source.py"}` are **Task 2** steps, because both require the
   loader Task 2 creates. Task 1 cannot reach GREEN on a test that references a
   symbol that does not yet exist, and every task must end clean.
3. Add a typing-integrity test asserting that no file under `src/crypto_lab`
   contains `type: ignore[import-untyped]`, `type: ignore[import-not-found]`,
   or a bare `type: ignore` on an `import` line. Under offline pressure this is
   the shortest route to a green mypy with an untyped trust boundary, and
   `warn_unused_ignores` will not flag it while the stubs are genuinely absent.
   **Preventive safety test; begins GREEN.**
4. Extend `test_mypy_untyped_import_override_is_exact` to assert
   `set(mypy) == {"python_version", "strict", "files", "overrides"}`. The
   existing assertion pins only `overrides`, so a top-level
   `ignore_missing_imports = true` or `disable_error_code = [...]` would relax
   typing repository-wide while leaving the test green.
   **Preventive safety test; begins GREEN** against the current
   `pyproject.toml`.
5. Update `_EXPECTED_RUNTIME_REQUIREMENTS` to `("pydantic>=2.12,<3",
   "pyyaml>=6.0.3,<7")` and add `types-pyyaml` to
   `_EXPECTED_DEVELOPMENT_NAMES`. **Meaningful RED 1:** `AssertionError`
   comparing the current one-element runtime tuple and the current seven-name
   development set, before `pyproject.toml` changes.
6. Add a lock test asserting that `uv.lock` contains a `types-pyyaml` package —
   so a silent stub-less install is caught — and that the locked `pyyaml`
   package has a `wheels` entry matching `cp312` and `win_amd64`. The existing
   `test_lock_registry_artifacts_are_sha256_pinned` does not distinguish sdist
   from wheel, and `no-build-isolation = true` means an sdist path would run
   PyYAML's `setup.py` against the project environment.
   **Meaningful RED 2:** the assertions fail against the unmodified `uv.lock`,
   before lock regeneration.
7. Update `pyproject.toml` to add `"pyyaml>=6.0.3,<7"` to
   `[project].dependencies` and `"types-pyyaml>=6.0.12,<7"` to
   `[dependency-groups].dev`.
8. Run the section 8 dependency flow. This closes meaningful RED 1 at the
   `pyproject.toml` edit, meaningful RED 2 at lock regeneration, and meaningful
   RED 3 at offline synchronization, in that order.
9. Record each of the three REDs and its matching GREEN in the ledger, with the
   exact message, and record the three preventive safety tests separately as
   having begun green.

**Minimum GREEN:** every guard test above passes and the environment
synchronizes offline.

**Focused verification**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\safety -q
```

**Broader verification:** `pytest-all`. **Also:** `ruff-format-all`,
`ruff-check-all`, `mypy-all`, `build`.

**Security review:** confirm no network command ran outside an approved
one-time acquisition; confirm the mypy override list is unchanged; confirm no
prohibited dependency family entered.

**Independent review gate:** required before commit.

**Commit:** `chore: add stage 4 safe yaml dependency`

### Task 2 — Safe YAML loader and strict strategy models

**Files:** `src/crypto_lab/domain/results.py`,
`src/crypto_lab/domain/__init__.py` (re-exports only),
`src/crypto_lab/domain/hashing.py` (adds `DIAGNOSTIC_IDENTITY_V1` and
`_uuid4_shaped` only), `src/crypto_lab/domain/capability_names.py`,
`src/crypto_lab/domain/capability_requirements.py`,
`src/crypto_lab/domain/comparison_levels.py`,
`src/crypto_lab/strategy/yaml_source.py`,
`src/crypto_lab/strategy/expressions.py`,
`src/crypto_lab/strategy/models.py`,
`tests/unit/domain/test_domain_results.py`,
`tests/unit/domain/test_domain_capability_contracts.py`,
`tests/unit/strategy/test_strategy_yaml_source.py`,
`tests/unit/strategy/test_strategy_yaml_bounds.py`,
`tests/unit/strategy/test_strategy_expressions.py`,
`tests/unit/strategy/test_strategy_models.py`,
`tests/fixtures/strategy/**` (see the ownership narrowing below),
`tests/safety/test_stage3_boundaries.py`,
`tests/safety/test_stage4_yaml_runtime.py`,
`tests/unit/test_package_layout.py`.

**Reviewed correction — Task 2's fixture glob is narrowed for the future, and
Task 2's commit is not reopened.** As written, `tests/fixtures/strategy/**` also
covers the paths section 6.5.3 assigns to Task 4, which would leave those paths
dually owned and would make Task 4's own pre-staging prohibition on "Task 2 test"
files contradict its enumerated fixture list. The glob is therefore read as:

```text
tests/fixtures/strategy/**  excluding
    invalid/feature_cycle.yaml
    warm_up_boundary.valid.yaml      crossover_equality.valid.yaml
    missing_input.valid.yaml         bar_offsets.valid.yaml
    decimal_rounding.valid.yaml      adjacent_entry_exit.valid.yaml
    golden/**
```

Task 2 authored the eleven fixtures it actually shipped at `9a2c73f` —
`sma_cross_long.{valid,reordered_keys,commented}.yaml` and eight `invalid/`
files — and none of the excluded paths. This narrowing is a **forward bookkeeping
correction to the plan text only**: it changes no committed file, requires no
Task 2 re-execution, and is not retroactive Task 2 work. Task 4 owns the excluded
paths outright per section 6.5.3.

Task 1 creates `tests/safety/test_stage4_yaml_runtime.py`; Task 2 extends it
with the two `StrictStrategySafeLoader` assertions and the yaml-import-closure
test of step 9, which is why both tasks list it.

Task 2 owns `DIAGNOSTIC_IDENTITY_V1` and the `_uuid4_shaped` helper in
`crypto_lab/domain/hashing.py`, because Task 2 is the first task that emits a
`Diagnostic` and section 5.3.3 makes that helper a precondition. Task 5 later
adds `STRATEGY_VERSION_V1` to the same enum.

**Consumes:** `CanonicalModel`, `Diagnostic`, `canonical_json_bytes`,
`sha256_bytes`, identifier and financial primitives.
**Produces:** `Result`, `Success`, `Failure`, `YamlDocument`,
`load_yaml_document`, `SourceName`, the closed discriminated `Expression`
union and its node models, `EngineExtensionDeclaration`, `Direction`,
`StrategySpec` and every other sub-model, and the relocated domain contracts
`CapabilityName`, `VocabularyVersion`, `CapabilityRequirement`,
`ApproximationPolicy`, and `ComparisonLevel`.

**`StrategySpec` fields** — exactly the twenty-one names in specification
section 12.2: `schema_version`, `strategy_id`, `display_name`, `description`,
`strategy_family`, `market_type`, `direction`, `timeframe`, `universe`,
`required_capabilities`, `parameters`, `features`, `entry_rules`, `exit_rules`,
`sizing_intent`, `risk_assumptions`, `warm_up_requirements`,
`comparison_requirements`, `supported_approximation_policy`,
`engine_extensions`, `authoring_metadata`.

**`schema_version` decision.** `StrategySpec.schema_version` is the literal
`"1.0.0"`, matching every other canonical record and the
`urn:...:strategy-spec:1.0.0` schema `$id`. Specification section 12.4's
`schema_version: strategy/v1` is illustrative source shape only — that section
states "This example communicates shape only." The YAML source token is
therefore `1.0.0`, and section 5.5's hashed `strategy_schema_version` carries
that literal. No source-token translation layer exists.

**Closed AST, owned here** — exactly the nodes in specification section
12.3.1, each a `CanonicalModel` with a `Literal` `op` discriminator:

```text
literal(value_type: BOOLEAN|INTEGER|DECIMAL|STRING|IDENTIFIER, value)
ref(id, bars_ago >= 0)
not(operand)            negate(operand)          is_missing(operand)
add, subtract, multiply, divide, minimum, maximum   (left, right)
equal, not_equal, less_than, less_than_or_equal,
  greater_than, greater_than_or_equal               (left, right)
and(operands: tuple, min_length=1)   or(operands: tuple, min_length=1)
crosses_above(left, right)           crosses_below(left, right)
```

`expression_semantics_version = "expressions/v1"`. Arithmetic returns
`DECIMAL`; comparison returns `BOOLEAN`; boolean operators accept booleans
only. There is no implicit string-to-number, float-to-Decimal,
asset-to-string, scalar-to-series, or timezone conversion. Expression nesting
is bounded by `MAX_EXPRESSION_DEPTH = 24`, which section 5.3 records alongside
the other ceilings. These definitions are hash material — `entry_rules` and
`exit_rules` sit inside `strategy_spec` in the section 5.5 payload — so they
are fixed here and no later task may change a node's field shape.

**`market_type` reuses the existing enum.** `MarketType` already exists in
`crypto_lab/domain/records.py` with `SPOT`, `MARGIN`, `FUTURES`, and
`EQUITIES`. `StrategySpec.market_type` imports it; Stage 4 does **not** define
a second `MarketType`. This must be stated because `MarketType` is not in
`_DEFERRED_DEFINITIONS`, so a duplicate landing in `strategy/models.py` would
pass every guard, and the enum is hash material. `Direction` genuinely does not
exist yet and is new in `strategy/models.py`.

**Enum casing decision.** `market_type` and `direction` are `StrEnum`s with
uppercase values, matching every merged enum in the repository
(`DiagnosticSeverity.INFO`, `OperatingSystem.WINDOWS`, `MarketType.SPOT`).
`CanonicalModel` is `strict=True` with no implicit coercion, so every YAML
source and every fixture must author `market_type: SPOT` and
`direction: LONG`. Specification sections 12.2 and 12.4 both write lowercase `spot`/`long`;
both are treated as illustrative source shape, since 12.4 states the example
"communicates shape only" and 12.2 names fields rather than fixing their
serialized casing. This casing is hash material and is fixed here, before any
`content_hash` is recorded. Initial policy accepts only `SPOT` and `LONG`;
every other vocabulary member is rejected with
`STRATEGY.POLICY_FORBIDDEN_MARKET` or `STRATEGY.POLICY_FORBIDDEN_DIRECTION`.

**Field lists for every schema-bearing model.** `StrategyVersion`,
`CapabilityRequirement`, `CapabilityDeclaration`,
`RuntimeAvailabilityObservation`, `CompatibilityResult`, and
`ComparisonEligibilityResult` take exactly the minimum fields their
specification section 11.3 rows list, in that order, with the state-governed
optionality of section 11.5. One documented addition: `StrategyVersion` also
carries `source_provenance: StrategySourceProvenance`, which section 11.3's row
does not list. Section 11.3 states *minimum* fields and section 5.5 requires
retained non-identity provenance, so this is an addition rather than a
deviation, and it is explicitly outside the hashed payload. The owning task adds a field-level acceptance
test per model asserting `set(Model.model_fields) == {...}` against the
literal specification list, so no field set is invented.

#### Reviewed correction — the four hash-material field types

**Scope of this correction.** Sections 12.2, 12.3.1, 12.6, and 11.3 name four
hash-material fields exhaustively but leave their **concrete types** unstated:
`literal.value`, `ApproximationPolicy`'s member list,
`CapabilityRequirement.minimum_semantics`, and the two
`EngineExtensionDeclaration` effect classifications. All four are frozen
permanently at Task 2, because `entry_rules`, `exit_rules`,
`required_capabilities`, `supported_approximation_policy`, and
`engine_extensions` all sit inside `strategy_spec` in the section 5.5 hash
payload. This correction resolves exactly those previously unstated types. It
changes no architecture, no roadmap entry, no task count, no task ordering, no
dependency decision, no unrelated file ownership, and no schema count, and it
**does not authorize Task 3 or any later-task behaviour**.

**A. Literal value contract.** The AST has exactly one `literal` node, not five
same-`op` union variants, and its type vocabulary is a `StrEnum` with uppercase
members `BOOLEAN`, `INTEGER`, `DECIMAL`, `STRING`, `IDENTIFIER`:

```python
class LiteralValueType(StrEnum):
    BOOLEAN = "BOOLEAN"
    INTEGER = "INTEGER"
    DECIMAL = "DECIMAL"
    STRING = "STRING"
    IDENTIFIER = "IDENTIFIER"
```

Its fields are `op: Literal["literal"]`, then `value_type: LiteralValueType`,
then `value: bool | int | Decimal | str`. **`value_type` must precede `value` in
model field order**, and validation must dispatch on the `(value_type, value)`
pair **before** ordinary union validation. Exact rules:

- `BOOLEAN` accepts only an exact `bool`.
- `INTEGER` accepts only an exact `int` and explicitly rejects `bool`.
- `DECIMAL` accepts only the existing canonical-decimal string representation at
  the YAML/JSON boundary — `crypto_lab.domain.financial`'s
  `CANONICAL_DECIMAL_PATTERN` form, reached through `parse_decimal` — and stores
  a `Decimal` in memory.
- `STRING` accepts an exact `str` and is never parsed merely because its text
  resembles a number, a boolean, or an identifier.
- `IDENTIFIER` accepts an exact `str` validated by the existing
  `NormalizedIdentifier` contract.
- `float`, `None`, list, tuple, set, mapping, callable, and arbitrary object
  values fail, and no implicit conversion occurs.
- A defensive post-validation invariant confirms the stored runtime type still
  agrees with `value_type`.
- `Decimal` serialization uses the existing canonical `format_decimal`
  serializer; an identifier serializes as its canonical string; and `value_type`
  remains part of canonical serialization and hashing.

Union ordering must not be used as validation, and `value` must not be typed
`Any` or `object`. Both prohibitions are load-bearing rather than stylistic: a
`STRING` literal whose text is `"1"` would validate as a canonical decimal under
any union mode that tries decimal first, and a `DECIMAL` literal would validate
as `str` under one that tries `str` first, so union ordering alone would put the
wrong Python type into a permanent `content_hash`.

**Field order is a validation-ordering requirement, not a hashing one.**
`canonical_json_text` passes `sort_keys=True` and specification section 10.2
mandates sorted keys, so declaration order cannot change a hashed byte. The
requirement exists because Pydantic populates `ValidationInfo.data` with only
the fields validated **so far, in declaration order**: `value_type` must
validate first or the dispatcher cannot see it. Reordering the two fields would
therefore silently disable the dispatch rather than change a hash.

**The dispatch mechanism is fixed here, because the prohibitions above rule out
every alternative.** Five same-`op` variants are forbidden by this item, union
ordering is forbidden by the paragraph above, and `Any`/`object` is forbidden
too. What remains is per-`value_type` dispatch that bypasses union routing
entirely, and it is normative:

- `value` is annotated `bool | int | Decimal | str` for typing and schema only.
  A project-owned validator attached to that annotation — a `PlainValidator`, or
  equivalently a wrap validator that ignores the supplied handler — reads
  `info.data["value_type"]` and invokes exactly one of five pre-built branches.
  No Pydantic union member is ever tried.
- The `DECIMAL` branch delegates to `crypto_lab.domain.financial.parse_decimal`,
  passing the same `ValidationInfo` so `info.mode` is honoured: a real `Decimal`
  in Python mode, an exact `CANONICAL_DECIMAL_PATTERN` string in JSON mode. This
  is the identical validator `CanonicalDecimal` itself uses, so the accepted
  text and the emitted bytes are the same as every other decimal field in the
  repository. `"1.50"` and `"1E+2"` are rejected at the JSON boundary, and a
  Python-mode `Decimal("1.50")` serializes to canonical `"1.5"` through
  `format_decimal`.
- A missing or non-member `value_type` — which happens whenever `value_type`
  itself failed validation, since the later validator still runs against a
  partial `info.data` — raises rather than indexing, so the dispatcher never
  raises `KeyError` out of the `Result` contract.
- The post-validation invariant compares **exact** runtime types
  (`type(value) is …`) and never `isinstance`, and tests `bool` before `int`.
  This is mandatory: `isinstance(True, int)` is `True` in Python, so an
  `isinstance` invariant would admit `True` as an `INTEGER` and put a JSON
  `true` where an integer belongs in a permanent `content_hash`.

**Each branch is bounded, not merely typed.** Section 5.3's
`MAX_SCALAR_CHARACTERS` and `MIN`/`MAX_INTEGER_VALUE` are **loader** bounds
applied during the event pass, so they do not constrain
`Expression.model_validate_json` or an external consumer of the generated
schema. Without per-branch bounds the model would admit values the loader
rejects, and a Python-mode integer beyond CPython's 4300-digit conversion limit
would raise an uncaught `ValueError` from inside `canonical_json_bytes` — the
exact failure section 5.3 closed for the loader, reached through the model
boundary instead. Therefore:

- `INTEGER` is bounded to signed 64-bit, following the existing
  `BoundedDetailInteger` precedent in `crypto_lab/domain/diagnostics.py` that
  section 5.3 already cites, and matching the loader's
  `MIN_INTEGER_VALUE`/`MAX_INTEGER_VALUE`.
- `STRING` is bounded to `MAX_SCALAR_CHARACTERS`.
- `IDENTIFIER` is bounded by `NormalizedIdentifier` itself, which carries its
  own pattern and its 1-to-128 length bound.

**The generated conditional schema is Task 2's, in `strategy/expressions.py`.**
Pydantic emits an unconstrained `anyOf` over the four scalar types on its own,
which this item forbids, and it will not emit a conditional unaided. The only
mechanism that needs no generator change is a `json_schema_extra` hook on the
literal node's `model_config`, exactly as `StrategyArtifactOwner` and
`AdapterArtifactOwner` already emit `oneOf` and `dependentRequired` in
`crypto_lab/artifacts/ownership.py`, and section 3.1 records that as the
established convention. That hook lives in `strategy/expressions.py`, which is a
**Task 2** file, and Task 8 creates no source file — so the obligation must land
with the model, in the same commit. Task 8 only regenerates and verifies the
emitted bytes.

Two constraints on that hook. It must make the `value_type`/`value` relationship
explicit with conditional or `oneOf` semantics covering **every** member of
`LiteralValueType`, so no unconstrained generic scalar union is exposed. And its
`DECIMAL` and `IDENTIFIER` branches must derive their sub-schemas from the
existing types — through a `$ref`, or `exact_string_schema`, or the type's own
emitted schema — and must never inline `CANONICAL_DECIMAL_PATTERN` or the
`NormalizedIdentifier` pattern literally. Both module constants are
`$`-terminated, and `test_every_schema_pattern_uses_absolute_end_semantics`
requires every emitted pattern to carry the ECMA-safe `(?![\s\S])` ending, so an
inlined pattern fails that guard and duplicates a hash-material pattern in a
second place where it can drift.

*Required focused tests, in `tests/unit/strategy/test_strategy_expressions.py`:*
a valid value for every `value_type`; every mismatched type pair; `bool` rejected
as `INTEGER`; an integer rejected as `DECIMAL`; a decimal-like string retained as
`STRING`; the same text represented as `DECIMAL` versus `STRING` producing
distinct canonical bytes; `IDENTIFIER` validating `NormalizedIdentifier`;
JSON-mode and YAML-loaded round trips; unknown-`value_type` rejection; and no
coercion.

**B. Approximation policy contract.** `ApproximationPolicy` is exactly:

```python
class ApproximationPolicy(StrEnum):
    REJECT = "REJECT"
    ALLOW_DECLARED = "ALLOW_DECLARED"
```

No other value exists in `strategy/v1`. `ALLOW_ANY`, `PREFER`, `AUTO`,
`BEST_EFFORT`, an implicit allow, and a wildcard policy are all prohibited. The
top-level supported-approximation-policy model keeps the structure section 12.4
shows, but its `strategy/v1` `default` is **required** and must be the literal
`REJECT`. Every `CapabilityRequirement.approximation_policy` is required and
explicit, with no injected default. `ALLOW_DECLARED` means only that a
machine-readable `ApproximationDeclaration` exists, that it is for the same
capability, and that its comparison-level exclusions are honored; it never
permits an unnamed or inferred approximation, which is what makes section 13.3
step 4 decidable.

**Precedence between the two, stated so section 13.3 step 4 has one answer.**
The per-requirement `CapabilityRequirement.approximation_policy` is
**authoritative for its own capability**. The top-level `default` is the
strategy-wide statement for capabilities the strategy does not individually
enumerate. In `strategy/v1` the two can never disagree in effect, because the
`default` is fixed to `REJECT` and no requirement may omit its own explicit
policy, so the resolver of Task 6 reads only the per-requirement value and the
`default` is never consulted during resolution. A requirement carrying
`ALLOW_DECLARED` beside the fixed `REJECT` default is therefore **not** a
contradiction and must not be rejected: the two govern disjoint sets. The
`default` is retained because it is declared hash material inside
`strategy_spec` and because it records, in the source, that approximation is not
accepted by default. Without this rule an implementer could read the `REJECT`
default as a ceiling and reject every `ALLOW_DECLARED` requirement, which would
make `SUPPORTED_WITH_APPROXIMATION` — one of the four outcomes acceptance gate
11 item 11 requires — unreachable.

*Required tests:* exact enum membership; unknown-value rejection; the top-level
default must be `REJECT`; a missing requirement policy fails; explicit `REJECT`
and `ALLOW_DECLARED` round-trip; no implicit default is injected into
`CapabilityRequirement`; and a spec carrying an `ALLOW_DECLARED` requirement
beside the fixed `REJECT` default is **accepted**, pinning the precedence rule
above.

**C. Minimum semantics contract.** For `strategy/v1`,
`CapabilityRequirement.minimum_semantics` is:

```python
minimum_semantics: Literal["capabilities/v1"]
```

It is required. It is not free-form text, not `SemanticVersion`, not optional,
not nullable, not inferred from the capability, and not imported from
`crypto_lab.adapters`. Only exact `capabilities/v1` is accepted; a future value
requires a new reviewed schema and vocabulary migration. The Task 6 resolver
compares this exact value with the descriptor's recognized
capability-vocabulary version before support resolution, satisfying section 13.3
step 1.

*Required tests:* the exact value accepted; a missing value rejected; `1.0.0`,
`v1`, `capability/v1`, `capabilities/v2`, the empty string, and `None` rejected;
and no coercion.

**D. Engine extension classifications.** The two effect fields of
`EngineExtensionDeclaration` are exactly:

```python
class ExtensionLifecycleEffect(StrEnum):
    LIFECYCLE_HOOKS_ONLY = "LIFECYCLE_HOOKS_ONLY"
    ALTERS_EXECUTION_BEHAVIOR = "ALTERS_EXECUTION_BEHAVIOR"


class ExtensionEconomicEffect(StrEnum):
    NONE = "NONE"
    PREVENTS_LEVEL_2 = "PREVENTS_LEVEL_2"
    PREVENTS_LEVEL_1_AND_LEVEL_2 = "PREVENTS_LEVEL_1_AND_LEVEL_2"
```

Both `lifecycle_effect` and `economic_effect` are required and reject unknown
values. `LIFECYCLE_HOOKS_ONLY` requires `economic_effect == NONE`, which is
specification section 12.6's "only adapt lifecycle hooks" alternative stated
executably. `ALTERS_EXECUTION_BEHAVIOR` may carry any economic-effect value.
`PREVENTS_LEVEL_2` excludes Level 2 but not automatically Level 1;
`PREVENTS_LEVEL_1_AND_LEVEL_2` excludes both. There is no bare
`PREVENTS_LEVEL_1` member, because specification section 25.2 makes Level 2 a
superset of Level 1, so preventing Level 1 necessarily prevents Level 2 and the
two-member form is complete.

**There is deliberately no `PREVENTS_LEVEL_3` member, and the reason is scope,
not impossibility.** Specification section 12.6 bounds an extension's declared
economic effect to exactly *"make a Level 1 or Level 2 comparison ineligible"*;
Level 3 is absent from that sentence, and section 25.3 explains why it would be
meaningless there, since Level 3 does not expect numerically identical results.
**This says nothing about `ApproximationDeclaration.prevented_comparison_levels`,
which is a different type owned by a later task and which specification sections
13.4 and 11.3 require to be able to include Level 3.** Conflating the two would
break the Task 7 eligibility test that rejects a requested level named in
`prevented_comparison_levels`. `ExtensionEconomicEffect` is narrower than
`ComparisonLevel` on purpose; it is not a claim that Level 3 can never be
excluded.

Both effect values are canonical hash material. The core stores declarations and
never imports or executes extension code.

**Module placement, because the source-file guard is exact set equality.**
`LiteralValueType` lives in `src/crypto_lab/strategy/expressions.py`;
`ExtensionLifecycleEffect` and `ExtensionEconomicEffect` live in
`src/crypto_lab/strategy/models.py` beside `EngineExtensionDeclaration`. No new
source file is created for any of the three, so Appendix C's
`_ALLOWED_SOURCE_FILES` additions and section 9.8's `_DEFERRED_DEFINITIONS`
removals are unchanged by this correction. None of the four new type names
appears in `_DEFERRED_DEFINITIONS`.

**Enum casing extends to the three enums this correction adds.** The casing
decision above is written for `market_type` and `direction`; `ApproximationPolicy`,
`ExtensionLifecycleEffect`, and `ExtensionEconomicEffect` follow it identically.
`CanonicalModel` is `strict=True`, so every YAML source and every fixture must
author `REJECT`, `LIFECYCLE_HOOKS_ONLY`, and `NONE` in uppercase. Specification
section 12.4's lowercase `default: reject` is illustrative source shape only, on
exactly the reading section 12.4 states of itself. A fixture copied verbatim from
12.4 fails Task 2 step 14, so this is a build instruction and not a note.

Task 2 lands only the immutable declaration and model surface that section 9.1
already assigns it in `strategy/models.py`. It must **not** implement Task 5
hashing or loader behaviour early: the section 5.5 item 5 `extension_hashes`
sort and `HashingProfile.STRATEGY_VERSION_V1` remain Task 5's.

**One ordering obligation is Task 2's, and it is distinct from that sort.**
Section 5.5 item 1 hashes `spec.model_dump(mode="json")` with no exclusions, so
the declared order of `StrategySpec.engine_extensions` is present in the hashed
bytes. Task 5 test 5 nevertheless requires that reordering the declared
extensions leave the `content_hash` unchanged. Those two are reconcilable only if
`StrategySpec` **normalizes** `engine_extensions` into a canonical order —
`(adapter_name, extension_id, version)`, the same key section 5.5 item 5 uses,
with uniqueness on that key — so two source orderings validate to one model. That
normalization belongs to `StrategySpec` in Task 2. Note that the merged
`_unique_sorted_text` precedent **rejects** an unsorted collection rather than
sorting it; that behaviour is correct for an adapter-produced descriptor but
would make Task 5 test 5 unsatisfiable for a human-authored source, so
`engine_extensions` normalizes instead of rejecting. Section 5.5 item 5's sort of
the extension `content_hash` values remains Task 5's and is unaffected.

*Required tests:* both exact enum memberships; unknown-value rejection for each;
`LIFECYCLE_HOOKS_ONLY` with a non-`NONE` economic effect rejected;
`ALTERS_EXECUTION_BEHAVIOR` accepted with every economic-effect value; the
absence of any `PREVENTS_LEVEL_3` and any bare `PREVENTS_LEVEL_1` member; and, in
step 14, two source orderings of `engine_extensions` validating to one identical
`StrategySpec`.

**Test-first sequence**

1. `Result` discriminates success from failure and cannot carry both.
   **Expected RED:** `ModuleNotFoundError: crypto_lab.domain.results`.
2. `load_yaml_document` rejects a `pathlib.Path` and a `str` path.
   **Expected RED:** `ModuleNotFoundError: crypto_lab.strategy.yaml_source`.
3. One test per forbidden tag, using `invalid/python_tag.yaml` and
   `invalid/unknown_tag.yaml`.
4. Duplicate keys, merge keys, two documents, empty document, BOM, non-UTF-8.
5. **All twenty-four classifier tests of section 5.2.1**, beginning with the
   premise test that an implicit scalar event's `tag` is `None`. That test is
   what stops the contract from silently reverting to reading `event.tag`.
   Tests 19 to 24 — the non-specific `!` tag, the `=` value token, the integer
   bounds, event-kind exhaustiveness, identifier survival, and directive
   rejection — are not optional extras; each closes a defect an earlier draft
   of this plan actually contained.
6. **All eighteen mapping-key shapes of section 5.2.2**, one test each,
   including the quoted merge key, the `=` key, the over-long key, and the
   duplicate-ordering test.
7. **The `SourceName` tests of section 5.2.3**, including the generated-schema
   agreement test.
8. One test per bound in section 5.3, including `invalid/billion_laughs.yaml`
   and `invalid/recursive_alias.yaml`.
9. Global-state test: `yaml.SafeLoader.yaml_constructors` unchanged after
   success and after every failure path, plus the two Task 2 assertions
   deferred from Task 1 — `"yaml_constructors" not in
   StrictStrategySafeLoader.__dict__` and `yaml.SafeLoader in
   StrictStrategySafeLoader.__mro__` — and the import-closure test asserting the
   yaml-importing file set is exactly `{"strategy/yaml_source.py"}`.
10. Fresh-state test: invalid then valid yields the same result as valid alone.
11. **Closed AST tests**, in `tests/unit/strategy/test_strategy_expressions.py`,
    which Task 2 owns because it owns `strategy/expressions.py`. An unknown
    `op` is rejected by the discriminated union — **Expected RED:**
    `ModuleNotFoundError: crypto_lab.strategy.expressions` — plus one
    acceptance and one arity-rejection test per node kind, discriminator
    closure, `bars_ago = -1` rejected at the model level, and a tree deeper
    than `MAX_EXPRESSION_DEPTH` rejected. This step also carries every literal
    test required by item A of the reviewed correction above.

    **This step must precede step 14.** Taking `StrategySpec` green requires
    the AST, because `entry_rules` and `exit_rules` are expression trees, so
    `strategy/expressions.py` exists from that moment on and the
    `ModuleNotFoundError` RED above can never be observed afterwards. The
    numbering in this section is temporal, not a grouping.
12. **`EngineExtensionDeclaration`** accepts its seven specification section
    12.6 fields and rejects an unknown one. **Expected RED:**
    `ModuleNotFoundError: crypto_lab.strategy.models`, which is an
    `ImportError` — at this position `models.py` itself does not exist yet.
    This too precedes step 14, for the same reason. This step also carries the
    extension-classification tests required by item D of the reviewed
    correction above, and at this position
    `tests/unit/strategy/test_strategy_models.py` must contain **only**
    `EngineExtensionDeclaration` coverage: a module-level import of
    `StrategySpec` would fail collection and leave this step with no clean
    GREEN. The `StrategySpec` tests are appended in step 14.
13. **Domain contract tests** in
    `tests/unit/domain/test_domain_capability_contracts.py` for
    `CapabilityName`, `VocabularyVersion`, `CapabilityRequirement`,
    `ApproximationPolicy`, and `ComparisonLevel`, and a test that
    `crypto_lab.domain.__all__` contains every name this task re-exports.
    **Expected RED:** `ModuleNotFoundError:
    crypto_lab.domain.capability_names`. This also precedes step 14: taking
    `StrategySpec` green requires all three domain modules, because
    `required_capabilities`, `supported_approximation_policy`, and
    `comparison_requirements` depend on them, so their RED is unobservable
    afterwards. This step also carries the approximation-policy and
    minimum-semantics tests required by items B and C of the reviewed
    correction above.
14. `StrategySpec` accepts `sma_cross_long.valid.yaml` and rejects an unknown
    field. This is deliberately **last** in the sequence: it is the step that
    forces every preceding type into existence, so every module-missing RED in
    this task must be recorded before it.

**Minimum GREEN:** each listed test passes with the smallest implementation.

**Focused verification**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\strategy -q
```

**Broader verification:** `pytest-all`. **Also:** `ruff-format-all`,
`ruff-check-all`, `mypy-all`, `schema-generate-check` (must still report the
existing 11 schemas unchanged, because Task 2 adds no registry entry).

**Security review:** re-read section 5.2 and 5.3 line by line against the
implementation; confirm `yaml` is imported in exactly one module.

**Independent review gate:** required before commit.

**Commit:** `feat: add safe yaml loading and strategy models`

### Task 3 — Static expression validation

**Files:** `src/crypto_lab/strategy/validation.py`,
`tests/unit/strategy/test_strategy_validation.py`,
`tests/safety/test_stage3_boundaries.py`,
`tests/unit/test_package_layout.py`.

**Consumes:** the closed discriminated `Expression` union from
`strategy/expressions.py`, which **Task 2** owns for the reason given in
section 9. Task 3 does not create or modify that file. Changing a node's field
shape here would silently move every `content_hash`, because `entry_rules` and
`exit_rules` sit inside `strategy_spec` in the section 5.5 hash payload and
Task 2 has already landed hand-reviewed golden fixtures against the Task 2
shape.

**Produces:** the static type and reference checker only. The per-node AST
tests belong to Task 2, which defined the union.

The closed AST itself — its node list, arity, `op` discriminator,
`expression_semantics_version`, and `MAX_EXPRESSION_DEPTH` — is specified in
Task 2, which owns `strategy/expressions.py`. Task 3 validates trees built from
it and changes none of those definitions.

**Test-first sequence**

1. A tree whose declared operand types do not satisfy its operator signature is
   rejected. **Expected RED:** `ModuleNotFoundError:
   crypto_lab.strategy.validation`. Note that "an unknown `op` is rejected" is
   **not** a Task 3 RED: the discriminated union Task 2 defined already rejects
   an unknown `op` at model construction, so that assertion is green before
   Task 3 begins and belongs to Task 2's suite.
2. Type-mismatch tests: boolean operand to `add`; decimal operand to `and`;
   string compared to integer.
3. A reference to an undeclared parameter, bar field, or feature is rejected
   with `STRATEGY.REFERENCE_UNKNOWN`. Note that `bars_ago = -1` is **not** a
   Task 3 case: Task 2's `ref(id, bars_ago >= 0)` rejects it at model
   construction and emits `STRATEGY.REFERENCE_NEGATIVE_OFFSET` there, so Task 3
   could not build such a tree to test.
4. `invalid/future_reference.yaml` is rejected with
   `STRATEGY.REFERENCE_FUTURE_BAR`. **Resolved, not outstanding — see section
   6.5.2.** The condition is unrepresentable in `expressions/v1`, the fixture is
   `NOT_CREATED_UNREACHABLE_IN_EXPRESSIONS_V1`, the specification section 12.3.3
   line 713 coverage requirement is discharged by named committed tests emitting
   `STRATEGY.REFERENCE_NEGATIVE_OFFSET`, and `STRATEGY.REFERENCE_FUTURE_BAR`
   remains reserved. This pointer is a plan-text cross-reference only; Task 3's
   committed implementation and tests are unchanged and not reopened.
5. Depth beyond `MAX_EXPRESSION_DEPTH` is rejected by the checker, complementing
   Task 2's model-level bound.
6. Diagnostics from a rule with several errors are complete, deduplicated, and
   sorted by `(rule_id, node_path, error_code)`. **Amended by section 5.4.2:**
   "complete" is bound-qualified by the governing sentence at section 5.4.1, and the
   key gains `canonical_json_bytes(details)` as a fourth component so that it is
   total. The three components stated here keep their meaning and their relative
   precedence, so this statement remains literally true; the fourth only breaks ties
   the first three admit. **Section 5.10** fixes where a spec-level finding — one
   with no rule — sorts, and the committed docstring asserting that a shared rule
   identifier leaves the sort key tied must be corrected, since the fourth component
   removes that tie.

**Focused verification:** `pytest-focused -o addopts= tests\unit\strategy -q`.
**Broader:** `pytest-all`. **Also:** Ruff, strict mypy.

**Security review:** confirm no operator name is resolved from a string at
runtime and no callable is stored in a model field. The union's closure is
Task 2's security review.

**Independent review gate:** required.

**Commit:** `feat: add strategy expression validation`

### Task 4 — Feature DAG and deterministic Level 1 evaluator

**Files:** `src/crypto_lab/strategy/feature_graph.py`,
`src/crypto_lab/strategy/evaluation.py`,
`tests/unit/strategy/test_strategy_feature_graph.py`,
`tests/unit/strategy/test_strategy_evaluation.py`,
`tests/property/test_expression_evaluation.py`,
`tests/fixtures/strategy/golden/**`,
`tests/fixtures/strategy/invalid/feature_cycle.yaml`,
`tests/fixtures/strategy/warm_up_boundary.valid.yaml`,
`tests/fixtures/strategy/crossover_equality.valid.yaml`,
`tests/fixtures/strategy/missing_input.valid.yaml`,
`tests/fixtures/strategy/bar_offsets.valid.yaml`,
`tests/fixtures/strategy/decimal_rounding.valid.yaml`,
`tests/fixtures/strategy/adjacent_entry_exit.valid.yaml`,
`tests/safety/test_stage3_boundaries.py`,
`tests/unit/test_package_layout.py`.

**Reviewed correction — Task 4 fixture ownership is exactly these eight
entries**, and no other fixture path is authorized:

```text
tests/fixtures/strategy/golden/**                       (expected output only)
tests/fixtures/strategy/invalid/feature_cycle.yaml
tests/fixtures/strategy/warm_up_boundary.valid.yaml
tests/fixtures/strategy/crossover_equality.valid.yaml
tests/fixtures/strategy/missing_input.valid.yaml
tests/fixtures/strategy/bar_offsets.valid.yaml
tests/fixtures/strategy/decimal_rounding.valid.yaml
tests/fixtures/strategy/adjacent_entry_exit.valid.yaml
```

Task 4 **consumes but does not own or recreate**
`tests/fixtures/strategy/sma_cross_long.valid.yaml`, which Task 2 committed at
`9a2c73f`.

Two distinct plan file-map omissions are corrected here, both of them omissions
rather than new behaviour, new features, Task 2 corrections, dependency changes,
schema changes, Task 5 work, or Stage 5 work:

1. **`invalid/feature_cycle.yaml`.** Task 4 step 2 has always required it, and
   Task 2 — which owned `tests/fixtures/strategy/**` — deliberately did not author
   it because its content depends on the feature-reference semantics Task 4 owns.
   Without this entry the step demands a path outside Task 4's file map.
2. **The six root `*.valid.yaml` golden inputs.** Section 6.5 defines two separate
   fixture roles: root-level `*.valid.yaml` files are complete `StrategySpec`
   **input** documents, and `tests/fixtures/strategy/golden/**` holds expected
   evaluator **output** JSON. Task 4's original Files list assigned only the
   output directory, yet steps 5 and 6 require the six named input strategies,
   which Task 2 never created. Task 4 therefore could not execute its own
   required golden tests. `golden/**` remains **exclusively** for expected
   evaluator outputs: the six inputs must **not** be relocated beneath it, must
   not be renamed, must not be merged into one general-purpose fixture, and
   `sma_cross_long.valid.yaml` must not be substituted for a scenario whose
   semantics it does not isolate.

Section 6.5.1 records the non-created disposition of every remaining orphaned
`invalid/` name. No further fixture path may be added to Task 4 without a new
human scope ruling.

**Produces:** `validate_feature_graph`, `topological_order`,
`evaluate_level_one`.

**Feature operations** — a closed allowlist with typed signatures:
`source.bar_field/v1`, `expression.project/v1`, `rolling.mean/v1`,
`rolling.sum/v1`, `rolling.min/v1`, `rolling.max/v1`, `shift/v1`,
`indicator.sma/v1`. Bar fields are exactly `bar.open`, `bar.high`, `bar.low`,
`bar.close`, `bar.volume`, `bar.timestamp_utc`.

**Semantics** — before a feature's declared warm-up completes its value is
`MISSING`. A top-level entry or exit rule containing `MISSING` evaluates to
false and never becomes true through truthiness. After warm-up the explicit missing-data policy applies. Per specification
section 12.3 the policy is declared **per feature**, as
`FeatureDefinition.missing_value_policy`, one of `REJECT_DATASET`, `SKIP_BAR`,
or `PROPAGATE_FALSE`; it is not one of the twenty-one top-level
`StrategySpec` fields. At bar `t`, `crosses_above(left, right)` is true exactly
when both series are present at `t` and `t-1`, `left[t] > right[t]`, and
`left[t-1] <= right[t-1]`; `crosses_below` uses the inverse inequalities.
Declared warm-up must be at least the maximum dependency warm-up.

**Test-first sequence**

1. A duplicate feature ID is rejected. **Expected RED:** module missing.
2. `invalid/feature_cycle.yaml` yields `STRATEGY.FEATURE_CYCLE` whose details
   list the cycle members in a deterministic rotation-normalized order; the
   same cycle declared in a different source order yields the identical
   diagnostic.
3. Topological order is stable and total: ties break by feature ID.
4. Declared warm-up below the dependency maximum is rejected.
5. Golden **feature** series for `warm_up_boundary`, `missing_input`,
   `bar_offsets`, and `decimal_rounding`, each against its section 6.5.3 pairing.
   **Reviewed correction:** `crossover_equality` moves to step 6. The approved
   step 5 listed it here, but section 6.5's inventory pairs it with
   `golden/crossover_equality.signals.json` and not a `.features.json` file, and
   the crossover equality edge is a **signal** boundary. The pairing table in
   section 6.5.3 is authoritative; no `crossover_equality.features.json` exists
   or is authorized.
6. Golden **signal** series for `sma_cross_long`, `crossover_equality`, and
   `adjacent_entry_exit`, each against its section 6.5.3 pairing. `sma_cross_long`
   additionally has a feature-series golden, per that same table.
7. Division by zero yields `STRATEGY.EVALUATION_DIVIDE_BY_ZERO`, not an
   exception or infinity.
8. A non-finite intermediate yields `STRATEGY.EVALUATION_NON_FINITE`.
9. A series longer than `MAX_EVALUATION_BARS` is rejected.
10. Property test: evaluation is a pure function of `(spec, bars)`; two calls
    with equal inputs return equal outputs; the global Decimal context is
    unchanged after evaluation.

**Reviewed correction — the Task 4 diagnostic combiner**

Task 4 is the first task that combines diagnostics from more than one producer,
so section 5.4.1's bounded-diagnostic contract binds it. The combiner must, in
this exact order:

1. **Combine** the relevant expression, graph, warm-up, duplicate-ID, and cycle
   diagnostics into one collection.
2. **Deduplicate** by `diagnostic_id`, which section 5.3.3 derives from the
   complete material payload.
3. **Apply the documented stable ordering** below.
4. **Return all** unique diagnostics when the count is at most 256.
5. **Return the first 255 plus the terminal marker** when the count exceeds 256,
   with the marker last.

**Task 4's documented total ordering key** is
`(error_code, source_component, canonical_json_bytes(details))`, and the
combiner's inputs satisfy section 5.4.1 item 0 — no correlation ID, empty
`causal_diagnostic_ids`.

**Why that key is total**, stated as a proof rather than asserted, because a
permutation test over a key that admits a genuine tie passes vacuously:

- `schema_version` is the fixed literal `"1.0.0"`.
- `category`, `severity`, `message`, and `retriable` are fixed functions of
  `(error_code, source_component)` through **each producer's** own closed per-code
  table, and are never interpolated from input. The pair, not `error_code` alone,
  is deliberate: `STRATEGY.EXPRESSION_TYPE_MISMATCH` and
  `STRATEGY.REFERENCE_UNKNOWN` are shared between `strategy.validation` and
  `strategy.feature_graph`, and Task 3's committed message literals for both are
  expression-worded, so a single per-code table would oblige the feature graph to
  describe a feature-input defect as an expression-operand defect. Each producer
  owns its own wording; the proof needs only this weaker premise, because
  `source_component` is already in the key.
- `source_component` is **in the key**, and is deliberately not claimed to be a
  function of `error_code`: the combiner merges diagnostics from more than one
  module, and `STRATEGY.EXPRESSION_TYPE_MISMATCH` and `STRATEGY.REFERENCE_UNKNOWN`
  are reachable from both `strategy.validation` and `strategy.feature_graph`, so
  that claim would be false.
- Every correlation ID is absent and `causal_diagnostic_ids` is empty, by item 0.

The section 5.3.3 identity payload is therefore a function of exactly
`(error_code, source_component, details)` — the key. Two entries equal on the key
have equal payloads and equal `diagnostic_id`s, so step 2 removed one of them
already. No tie can reach the sort, and generation order can never influence
either the retained set or its sequence.

Task 4 **must not** modify `src/crypto_lab/domain/results.py`. `Failure` and
`MAX_RESULT_DIAGNOSTICS` stay exactly as Task 2 committed them. If focused
evidence later proves that modifying `domain/results.py` is unavoidable, stop and
request a separate scope ruling rather than editing it.

Task 4 **must not** modify Task 3's `validate_strategy_expressions` unless a
focused regression proves that Task 3's own implementation independently violates
the 256-diagnostic contract. See section 5.4.1's scope paragraph.

**Cross-reference correction.** Section 5.4.1's scope paragraph has since been
superseded on one point by **section 5.4.2**, which requires Task 3 to adopt the
bounded-output policy. The restriction above still stands **as written, for
Task 4**: it bound Task 4, Task 4 is committed at
`2b8601fb3db4d43691586fd5253cb3473d5248a0` without having modified Task 3, and
nothing here retroactively authorizes Task 4 to do so. The work section 5.4.2
mandates is performed by the standalone pre-Task-5 corrective landing described in
section 5.10, which is not Task 4 and is not bound by this sentence.

**Reviewed correction — a detected cycle gates warm-up and topological order**

This is a **fourth** reviewed change, recorded as such. It is not one of the three
rulings above; it is the consequence that makes step 2 executable at all, and it
is named in Task 9's plan-history entry alongside them.

Warm-up sufficiency and topological order are **undefined** on a cyclic feature
graph: there is no dependency maximum to compare against and no total order to
produce. When `validate_feature_graph` detects a cycle it therefore returns the
cycle diagnostic — together with any diagnostic that does not depend on acyclicity,
namely duplicate-ID, unknown-operation, feature-input-existence, and typed-input
findings — and attempts neither warm-up validation nor topological ordering.

This rule is what makes step 2's own requirement checkable — that
`invalid/feature_cycle.yaml` "yields `STRATEGY.FEATURE_CYCLE` whose details list
the cycle members in a deterministic rotation-normalized order" and that "the same
cycle declared in a different source order yields the identical diagnostic". A
warm-up diagnostic computed from a cyclic dependency maximum would be
nondeterministic in exactly the way step 2 forbids, so gating it is required, not
merely tidy. It also lets the fixture assert `STRATEGY.FEATURE_CYCLE` without an
unrelated warm-up diagnostic appearing beside it.

**Reviewed correction — additional exact Task 4 tests**

These are required in addition to the ten steps above, and each is a named test,
not a note:

1. **255 unique diagnostics** → 255 returned, **no** marker present.
2. **256 unique diagnostics** → 256 returned, **no** marker present; this is the
   exact boundary at which diagnostics are still complete.
3. **257 unique diagnostics** → exactly 256 returned: 255 substantive plus the
   marker, and the marker is the **last** element.
4. **Deduplication precedes limiting** — a collection whose duplicates would push
   it past the bound returns its unique diagnostics in full with no marker,
   proving the bound counts unique diagnostics rather than raw findings.
5. **Source-order permutation produces byte-identical bounded output** — the same
   defects declared in a different source order yield the identical returned
   tuple, compared as canonical bytes, at the 255, 256, and 257 sizes.
6. **No expected-boundary exception escapes** — each of the three sizes is
   asserted to return a `Result`, with the test failing on any raised exception
   rather than tolerating one.
7. **No silent slicing** — a 257-diagnostic case is asserted to be
   distinguishable from a 256-diagnostic case by the returned tuple alone.
8. **The existing `Failure` schema is unchanged** — `MAX_RESULT_DIAGNOSTICS`,
   `Failure.model_fields`, and the `min_length`/`max_length` metadata on
   `Failure.diagnostics` are pinned, so a later edit to `domain/results.py` fails
   a test rather than passing silently.

**Reviewed correction — additional exact feature-signature tests**

Specification section 12.3.1 **line 701** is normative: "A feature graph must be
acyclic, every input must exist and type-check, and declared warm-up must be at
least the maximum dependency warm-up." Task 4's ten steps above cover acyclicity
(step 2) and warm-up (step 4) but named no test for the operation allowlist or for
input existence and type-checking, and section 6.5.1 rows 3 and 4 discharge only
the **expression-level** reading of the two removed fixture names. These three
named tests close that gap, all inside Task 4's existing scope and all using codes
already present in the section 5.9 closed table:

1. An `operation` outside Task 4's closed feature-operation allowlist yields
   `STRATEGY.FEATURE_UNKNOWN_OPERATION`. This code appears nowhere in `src/` or
   `tests/` before Task 4, and `FeatureDefinition.operation` is pattern-validated
   only, so an operation such as `bogus.thing/v1` constructs cleanly at the model
   level — the check is genuinely Task 4's to add.
2. A feature `input` naming neither a permitted bar field nor a declared feature
   yields `STRATEGY.REFERENCE_UNKNOWN`. `_reference_scope` in Task 3's
   `validation.py` never inspects `feature.inputs`, so no committed check covers
   this.
3. A feature `input` or `parameter` whose declared type does not satisfy its
   operation's typed signature yields `STRATEGY.EXPRESSION_TYPE_MISMATCH`. Task 4
   authors those typed signatures itself — the plan fixes the eight operation names
   and their bar-field vocabulary but no signature's arity, input types, parameter
   types, or output type — so this test is asserted against the signatures Task 4
   lands in the same commit, exactly as section 7 requires of any behaviour a task
   introduces.

All three are authored as **in-module `StrategySpec` trees, not fixture files**,
per section 6.5.4's rule that a case whose expected error code is the whole
assertion belongs in the test module. Test 1 in particular is **not** a licence to
create `invalid/unknown_operation.yaml`, which section 6.5.1 row 3 declines; no
further fixture path is authorized. The host module
`tests/unit/strategy/test_strategy_feature_graph.py` is already in Task 4's Files
list.

**Reviewed correction — additional exact golden-fixture tests**

Required alongside steps 5 and 6, each a named test:

1. Every one of the six root input paths **exists**.
2. Every input is UTF-8, **BOM-free**, and **LF-only**.
3. Every input loads to a valid `StrategySpec` through the safe loader.
4. Every input passes Task 3 static expression validation.
5. Every expected golden JSON file **exists**, at its section 6.5.3 pairing.
6. Expected and actual series lengths both equal the bounded input-bar count.
7. The **complete** series matches, not merely selected bars.
8. Numeric values are compared through exact `Decimal` or canonical-string
   semantics — never through `float`.
9. `MISSING` values are represented through the approved explicit contract.
10. No test silently regenerates or rewrites a golden file.
11. The six scenarios are **behaviourally distinct** rather than aliases of the
    same strategy.
12. The `sma_cross_long` golden tests — authored earlier in this same task, since
    Task 4 owns `golden/**` and no strategy-golden test exists before Task 4 —
    continue to pass unchanged as the other five scenarios are added. `sma_cross_long`
    is the one scenario whose **input** Task 2 already committed, so it is the
    regression anchor for the rest.

**Reviewed correction — exact Task 4 path and scope check before staging**

Before staging, `git diff --cached --name-only` must list exactly these **22**
paths — the **fourteen** non-`golden/` paths and the **eight** `golden/**`
members Task 4 owns — and nothing else:

```text
src/crypto_lab/strategy/feature_graph.py
src/crypto_lab/strategy/evaluation.py
tests/unit/strategy/test_strategy_feature_graph.py
tests/unit/strategy/test_strategy_evaluation.py
tests/property/test_expression_evaluation.py
tests/fixtures/strategy/invalid/feature_cycle.yaml
tests/fixtures/strategy/warm_up_boundary.valid.yaml
tests/fixtures/strategy/crossover_equality.valid.yaml
tests/fixtures/strategy/missing_input.valid.yaml
tests/fixtures/strategy/bar_offsets.valid.yaml
tests/fixtures/strategy/decimal_rounding.valid.yaml
tests/fixtures/strategy/adjacent_entry_exit.valid.yaml
tests/fixtures/strategy/golden/warm_up_boundary.features.json
tests/fixtures/strategy/golden/missing_input.features.json
tests/fixtures/strategy/golden/bar_offsets.features.json
tests/fixtures/strategy/golden/decimal_rounding.features.json
tests/fixtures/strategy/golden/sma_cross_long.features.json
tests/fixtures/strategy/golden/sma_cross_long.signals.json
tests/fixtures/strategy/golden/crossover_equality.signals.json
tests/fixtures/strategy/golden/adjacent_entry_exit.signals.json
tests/safety/test_stage3_boundaries.py
tests/unit/test_package_layout.py
```

No `pyproject.toml`, `uv.lock`, `scripts/`, `schemas/`, schema-registry,
`README.md`, `AGENTS.md`, `docs/`, `domain/results.py`, Task 2 source or test,
Task 3 source or test, or Stage 4 boundary-guard path may be staged. "Task 2 test"
here excludes the eight fixture entries section 6.5.3 transfers to Task 4, and
includes every fixture Task 2 shipped at `9a2c73f` — in particular
`sma_cross_long.{valid,reordered_keys,commented}.yaml` and the eight `invalid/`
files other than `feature_cycle.yaml`, none of which Task 4 may modify. Appendix C's
Task 4 subset is exactly `"strategy/evaluation.py"` and
`"strategy/feature_graph.py"` added to `_ALLOWED_SOURCE_FILES`; Appendix J's is
exactly `crypto_lab.strategy.evaluation` and `crypto_lab.strategy.feature_graph`
appended to `PACKAGE_MODULES`. Task 4 removes no `_DEFERRED_DEFINITIONS` name and
leaves the schema count at 11.

**Reviewed correction — future-reference handoff, closed**

Task 4 is the earliest possible owner of `STRATEGY.REFERENCE_FUTURE_BAR` and
hereby records the final `strategy/v1` disposition, set out in full in section
6.5.2: non-negative `bars_ago` names a current or historical **closed** bar only;
negative `bars_ago` is rejected before evaluation; an attempted future or
still-open bar is **unrepresentable** in `expressions/v1`; Task 4 therefore adds
no `future_reference` fixture, no `REFERENCE_FUTURE_BAR` evaluator branch, and no
negative-offset workaround; and the code remains **reserved** in the section 5.9
closed table for a future version whose grammar can represent that condition.

**Focused verification:** `pytest-focused -o addopts= tests\unit\strategy tests\property -q`.
**Broader:** `pytest-all`. **Also:** Ruff, strict mypy.

**Security review:** confirm the evaluator has no wall-clock, filesystem,
network, engine, or random access, and that it produces no order, fill, or
portfolio value.

**Independent review gate:** required.

**Reviewed correction — what the Task 4 implementation reviewer must do.** The
reviewer inspects all six root input YAML documents and every expected JSON file
**directly**, and independently challenges at least: warm-up off-by-one
behaviour; crossover **equality** boundaries; missing-input propagation; positive
bar offsets; `Decimal` rounding and negative-zero handling; adjacent entry/exit
timing; complete-series length and alignment; whether each expected JSON was
**independently authored** rather than copied from the evaluator; and whether
mutating evaluator behaviour actually causes the corresponding golden test to
fail. The reviewer must also mutation-test or otherwise independently challenge
cycle-order invariance, feature-ID tie breaking, diagnostic deduplication, the
256/257 boundary, the marker's terminal position, the absence of any escaping
exception, and `Decimal`-context restoration.

**Commit:** `feat: add feature graph and level 1 evaluator`

### Task 5 — Strategy versioning, extension declarations, and hashing

**Files:** `src/crypto_lab/domain/hashing.py`,
`src/crypto_lab/strategy/versioning.py`, `src/crypto_lab/strategy/loader.py`,
`tests/unit/strategy/test_strategy_versioning.py`,
`tests/unit/strategy/test_strategy_loader.py`,
`tests/property/test_strategy_hashing.py`,
`tests/safety/test_stage3_boundaries.py`,
`tests/unit/test_package_layout.py`.

**Consumes:** `EngineExtensionDeclaration` from `strategy/models.py`, which
Task 2 owns for the reason given in section 9.

**Produces:** `StrategySourceProvenance`, `StrategyVersion`,
`strategy_version_hash`, `StrategyLoader`.

`StrategyLoader.load(source: bytes, source_name: SourceName, observed_at_utc:
datetime) -> Result[StrategyVersion]`. This matches specification section 8.2's
operation contract; `SourceName` is the constrained non-path label of section
5.2, which narrows section 8.2's `str` without changing parameters, ownership,
sync behaviour, or result semantics.

`EngineExtensionDeclaration`, defined by Task 2, carries the seven fields fixed
there. Task 5 consumes them unchanged. The core stores declarations and hashes
and never imports or executes extension code. An extension whose declared economic effect prevents
parity makes Level 1 or Level 2 comparison ineligible.

**Test-first sequence**

1. `HashingProfile.STRATEGY_VERSION_V1` exists. **Expected RED:**
   `AttributeError`.
2. `sma_cross_long.valid.yaml`, `.reordered_keys.yaml`, and `.commented.yaml`
   produce an identical `content_hash`.
3. Changing any material field changes the hash.
4. Changing `source_name`, `observed_at_utc`, or `strategy_version_id` does
   **not** change the hash.
5. Adding, removing, or altering one extension hash changes the
   `content_hash`; reordering the declared extensions does not.
6. A `StrategyVersion` is frozen and rejects mutation.
7. **Two** property tests, replacing any key-permutation property. A
   canonical-JSON key-permutation property would be tautological here, because
   `canonical_json_text` sorts keys by construction and a validated
   `StrategySpec` is a Pydantic model with fixed field order, so there is no
   permutation left to observe.
   - *Formatting invariance:* generate a bounded valid spec, **render it back
     to YAML source text** under randomised mapping order, inserted comments,
     block-versus-flow style, and quoting style; load every variant through
     `StrategyLoader`; assert a single `content_hash`. This exercises the claim
     section 5.5 actually makes.
   - *Material sensitivity:* generate two specs differing in exactly one
     material field, and assert their hashes differ.

   Generators must draw **plain data** and construct models in the test body.
   They must not call `st.builds` inside the draw phase, which is the
   documented cost driver behind the earlier owner-hash slowdown and would be
   far worse for a 21-field model with nested expression trees.

   For accuracy: commit `e1c821453459f5eccf86a472e9204b6a90829d64` established
   that the owner-hash property is **meaningful** (it added an explicit guard
   against self-comparison) and **cheaper** (constructive alphabet strategies
   replaced `from_regex`). It did **not** remove the suppression —
   `tests/property/test_artifact_ownership.py` line 207 still carries
   `@settings(suppress_health_check=[HealthCheck.too_slow])` with a recorded
   justification. Section 11.1's four conditions govern any Stage 4
   suppression; this task adds no separate ban.

**Focused verification:** `pytest-focused -o addopts= tests\unit\strategy tests\property -q`.
**Broader:** `pytest-all`. **Also:** Ruff, strict mypy.

**Security review:** confirm no filesystem path, wall-clock value, machine
identity, or ambient value enters the hashed payload.

**Independent review gate:** required.

**Commit:** `feat: add strategy versioning and hashing`

### Task 6 — Capability vocabulary and deterministic compatibility resolver

**Files:** `src/crypto_lab/domain/descriptors.py`,
`src/crypto_lab/domain/__init__.py` (re-exports only),
`src/crypto_lab/domain/identifiers.py`,
`src/crypto_lab/adapters/descriptors.py`,
`src/crypto_lab/capabilities/vocabulary.py`,
`src/crypto_lab/capabilities/models.py`,
`src/crypto_lab/capabilities/policy.py`,
`src/crypto_lab/capabilities/resolver.py`,
`tests/unit/capabilities/test_capability_vocabulary.py`,
`tests/unit/capabilities/test_capability_models.py`,
`tests/unit/capabilities/test_capability_policy.py`,
`tests/unit/capabilities/test_capability_resolver.py`,
`tests/unit/domain/test_domain_descriptors.py`,
`tests/property/test_compatibility_resolution.py`,
`tests/architecture/test_package_import_boundaries.py`,
`tests/safety/test_stage3_boundaries.py`,
`tests/unit/test_package_layout.py`.

The four capability test modules are named individually rather than as a glob,
because `tests/unit/capabilities/test_capability_comparison.py` belongs to
Task 7.

`domain/capability_names.py`, `domain/capability_requirements.py`, and
`domain/comparison_levels.py` are **Task 2** files, per section 5.7 item 6.
Task 6 imports and re-exports from them and does not create them.
`tests/unit/domain/test_domain_descriptors.py` is a Task 6 file because its
whole subject — `domain/descriptors.py` and `RuntimeAvailabilityObservation` —
is created here, four tasks after Task 2.

**Vocabulary `capabilities/v1`** — exactly the 26 names in specification
section 13.1 (4 market, 2 direction, 4 data, 6 execution, 3 portfolio,
4 research, 3 runtime): `market.spot`, `market.margin`, `market.futures`,
`market.equities`; `direction.long`, `direction.short`; `data.ohlcv`,
`data.trades`, `data.quotes`, `data.order_book_l2`; `execution.bar_market`,
`execution.bar_limit`, `execution.event_driven`, `execution.maker_orders`,
`execution.partial_fills`, `execution.multiple_open_orders`;
`portfolio.single_asset`, `portfolio.multi_asset`, `portfolio.multi_venue`;
`research.parameter_sweep`, `research.optimization`, `research.monte_carlo`,
`research.walk_forward`; `runtime.backtest`, `runtime.paper`, `runtime.live`.

**Resolution order** — exactly specification section 13.3, steps 1 to 7. Core
safety-policy validation runs **before** resolution: a prohibited request
including `runtime.live`, credentials, shorting, margin, futures, or leverage
produces a `USER_CONFIGURATION` diagnostic and **no** `CompatibilityResult`.

The resolver returns all reasons in stable capability-name order. It never
stops at the first missing capability, never guesses from an engine name, and
never treats runtime absence as strategy incompatibility. It performs no
majority voting, no averaging of engine results, no synthetic combined returns,
and no strategy execution.

**Test-first sequence**

1. Vocabulary contains exactly 26 names and rejects an unknown name.
   **Expected RED:** module missing.
2. `runtime.live` in a request is rejected before resolution, with no
   `CompatibilityResult` produced.
3. All required native and runtime available yields `SUPPORTED`.
4. One unsupported or absent required capability yields `NOT_APPLICABLE` with
   the **complete** list of unmet requirements, not the first.
5. A required approximation the strategy permits, runtime available, yields
   `SUPPORTED_WITH_APPROXIMATION` with all approximation records.
6. A disallowed approximation yields `NOT_APPLICABLE`.
7. An approximation preventing the requested level yields `NOT_APPLICABLE`.
8. Semantically compatible but not runnable yields `UNAVAILABLE`, distinct from
   `NOT_APPLICABLE` and never counted as a strategy failure.
9. Reasons are stable, complete, deduplicated, and sorted by capability name.
10. Property test: permuting the input requirement and declaration order yields
    a byte-identical `CompatibilityResult`.
11. Architecture test: `crypto_lab/capabilities/**` imports **nothing** from
    `crypto_lab.adapters`, and nothing from `experiments`, `datasets`,
    `artifacts`, `persistence`, `process_supervision`, `configuration`,
    `audit`, or `cli`. The same test asserts `crypto_lab/strategy/**` imports
    only from `crypto_lab.domain`.
12. `schema-generate-check` proves
    `schemas/protocol/adapter-descriptor-v1.schema.json` is byte-identical after
    the `CapabilityName` relocation. **This gate is mandatory and blocking.**

**Focused verification:** `pytest-focused -o addopts= tests\unit\capabilities tests\architecture -q`.
**Broader:** `pytest-all`. **Also:** Ruff, strict mypy, `schema-generate-check`.

**Security review:** confirm the resolver is pure, executes no strategy, reads
no runtime, and that `runtime.live` cannot reach an outcome.

**Independent review gate:** required, and must explicitly confirm or reject
the section 5.7 dependency-direction decision.

**Commit:** `feat: add capability vocabulary and compatibility resolver`

### Task 7 — Approximation records, comparison levels, and eligibility

**Files:** `src/crypto_lab/capabilities/comparison.py`,
`tests/unit/capabilities/test_capability_comparison.py`,
`tests/safety/test_stage3_boundaries.py`,
`tests/unit/test_package_layout.py`.

**Consumes:** `ComparisonLevel` from `crypto_lab.domain.comparison_levels`,
produced by **Task 2** per section 5.7 item 6, and `ApproximationDeclaration`
from `crypto_lab.capabilities.models`, produced by **Task 6**. Task 7 produces
neither and lists neither file.

**Produces:** `ComparisonEligibilityOutcome` (`ELIGIBLE`, `INELIGIBLE`,
`ELIGIBLE_WITH_DECLARED_DIFFERENCES`), `ComparisonEligibilityResult`,
`DifferenceCategory`, and the pure eligibility predicate of section 5.8.

`DifferenceCategory` is exactly the fourteen categories of specification
section 20.4: input or data alignment; warm-up behavior; indicator
implementation; signal timing; order timing; fee modeling; slippage modeling;
precision or rounding; partial-fill behavior; portfolio accounting;
engine-native execution semantics; declared approximation; normalization
limitation; unexplained difference. An unexplained difference blocks any claim
of parity at the affected level.

`ApproximationDeclaration` carries `schema_version`, `approximation_id`,
`capability`, `method`, `expected_impact`, `prevented_comparison_levels`
(an ordered unique set), and `adapter_version`. A result excluded from a level
cannot enter that level's comparison set.

**Test-first sequence**

1. Requested versus achieved level are distinct fields and both are recorded.
   **Expected RED:** module missing.
2. Level 1 eligibility requires matching strategy hash, dataset hash, warm-up,
   feature-semantics version, parameters, universe, and Decimal rules.
3. Level 2 additionally requires every assumption in specification section 25.2.
4. Level 3 records side-by-side provenance and never averages.
5. An approximation whose `prevented_comparison_levels` includes the requested
   level makes the comparison ineligible with
   `COMPARISON.APPROXIMATION_EXCLUDES_LEVEL`.
6. Ineligibility reasons are stable, complete, deduplicated, and deterministically
   ordered.
7. Tests assert the **absence** of any averaging, majority-vote, or synthetic
   combined-return function in the module's public surface.

**Focused verification:** `pytest-focused -o addopts= tests\unit\capabilities -q`.
**Broader:** `pytest-all`. **Also:** Ruff, strict mypy.

**Security review:** confirm no result combination, no promotion, and no
strategy execution.

**Independent review gate:** required.

**Commit:** `feat: add comparison levels and eligibility`

### Task 8 — Generated schemas, distribution, documentation, and acceptance

**Files:** `src/crypto_lab/schema_registry.py`, `schemas/strategy/**`,
`schemas/capabilities/**`, `tests/safety/test_stage3_boundaries.py`,
`tests/unit/test_schema_registry.py`, `docs/development/verification.md`,
`README.md`.

**Task 8 owns:** the nine generated schemas; schema distribution; verification
documentation; `README.md`; the complete implementation acceptance of section
11; and the Stage 4 implementation commit.

**Task 8 must not write its own hash into the roadmap**, and does not modify
`docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md` at all. A task
cannot record the hash of the commit that contains it, and a placeholder
corrected afterwards would leave the roadmap disagreeing with history. Task 9
records Stage 4 completion against Task 8's committed hash.

**Test-first sequence**

1. Update `assert len(paths) == 11` to `20` in
   `test_schema_registry_is_closed_and_protocol_descriptors_are_located_correctly`.
   **Expected RED:** `AssertionError: assert 11 == 20`.
2. Add the nine `SchemaDefinition` entries of section 6.3 to
   `SCHEMA_DEFINITIONS` in the order listed.
3. Run `schema-generate-write`, then review every generated file by hand
   before staging it. Generated bytes are reviewed source, not incidental
   output.
4. Run `schema-generate-check` and confirm a clean result.
5. Prove the eleven Stage 3 schemas are byte-identical:

```powershell
git diff --stat main..HEAD -- schemas/domain schemas/configuration `
  schemas/datasets schemas/protocol schemas/artifacts
```

   This must report **no changes**. Any change requires an independently
   approved architecture correction that owns it.
6. Confirm `_ALLOWED_SOURCE_FILES`, `_ALLOWED_IMPORT_ROOTS`, and
   `_DEFERRED_DEFINITIONS` are already complete. Task 8 creates no source file,
   defines none of the fourteen deferred names, and the four import roots were
   added once in Task 2, so all three lists finished at Task 7. Task 8's only
   legitimate edits to that module are the `11` to `20` schema count in step 1
   and the README status-line assertion in step 7. If any of the three lists is
   still incomplete here, an earlier task ended dirty — stop and repair that
   task rather than patching it in Task 8.
7. Update `docs/development/verification.md` with Stage 4 focused checks and
   the 20-file registry, and `README.md` with the status line and a
   strategy-loading summary.

   **README placement is constrained.**
   `test_readme_uses_only_closed_stage3_launcher_setup` partitions on
   `"## Local setup\n"` and `"\n## Explicit configuration and schemas"` and
   then compares the trailing prose block with `==`. Any sentence or heading
   inserted between those two markers fails it. New Stage 4 content therefore
   goes **after** `## Explicit configuration and schemas`. Also update
   README's "exactly those 11 schemas" sentence to 20 — it sits outside the
   pinned block and is otherwise left false. The status line is the one
   assertion Task 8 may update in the guard, per the section 3.9
   status-authority rule. Its exact replacement text is
   `**Status:** Project 1 Stages 1-4 complete`, and the guard assertion becomes
   that string verbatim. Task 8 lands one commit before Task 9 records Stage 4
   in the roadmap; that ordering is intended, because Task 8 *is* the
   implementation commit and Task 9 only records its hash.

   Three further assertions in that test are scoped to the **whole file**, not
   the partitioned block: `"\nuv sync "`, `"\nuv run "`, and
   `"Task 2 bootstrap"` must each remain absent. A correctly placed Stage 4
   summary can still fail on the first two, so write launcher profiles, never
   bare `uv sync` or `uv run`, anywhere in `README.md`.

   Leave README's Stage 3 acquisition prose at lines 65 to 66 unchanged. It
   names the Stage 3 Task 1 `sync-acquire` profile and becomes stale once Stage
   4 Task 1 exercises the section 8 flow, but it is pinned verbatim by the
   partitioned-block comparison and no Stage 4 task is authorised to correct
   it. Record the staleness in the ledger for a later documentation change.
8. Confirm every acceptance gate in section 11 has fresh offline evidence. The
   roadmap is deliberately untouched; Task 9 owns it.

**Focused verification:** `pytest-focused -o addopts= tests\safety tests\unit -q`.
**Broader:** the complete verifier `scripts/verify.ps1`, which must pass on the
first attempt with no pass-on-rerun.

**Security review:** implementation-scope review against section 5 and against
the Stage 4 exclusion list.

**Independent review gate:** required before commit, covering schema ownership,
documentation accuracy, and implementation acceptance.

**Commit:** `feat: complete project 1 stage 4 implementation`

### Task 9 — Stage 4 completion status and executable status guard

**Runs only after Task 8 is committed**, because it records that commit's exact
hash.

**Files, exactly two:**
`docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md` and
`tests/safety/test_stage3_boundaries.py`, or whichever module then holds the
exact roadmap-status guard.

**Consumes:** the committed Task 8 hash.
**Produces:** the recorded Stage 4 completion status and its executable guard.

**Test-first sequence**

1. Read the Task 8 commit hash with `git rev-parse HEAD` immediately after that
   commit, and record it in the ledger before editing anything.
2. Add a Stage 4 completion guard alongside the existing
   `test_stage3_completion_status_is_exact`, **and replace the not-started
   assertions in the plan-approval guard** that the separate roadmap-and-guard
   commit introduced, so the two do not contradict each other. Pin the exact
   roadmap text as module constants: the Task 8 implementation hash, the
   corrected-plan approval hash, and the launcher bootstrap prerequisite
   `350fac49ff5b1db4ec62b60c7ade76580f9894dd`.
   **Expected RED:** `AssertionError`, because the roadmap still records Stage 4
   implementation as not started.
3. Update the Stage 4 row of roadmap section 9, and the roadmap status line,
   to record:
   - **Stage 4 implementation complete at the Task 8 commit** — the
     implementation hash is Task 8's, never Task 9's;
   - that **Stage 4 status finalization at Task 9 is not represented as the
     implementation hash**. Task 9's own commit is a status-recording commit and
     must be described as such, exactly as the Stage 3 row distinguishes its
     implementation commit from its later stability correction;
   - that **Stage 5 remains not started**, with its plan still deferred and its
     exit gate not evaluated.
4. Keep the executable roadmap guard exact: every pinned string must be a
   verbatim substring of the roadmap, and the guard must fail if the roadmap
   text drifts. Do not relax any existing Stage 3 assertion.
5. Confirm no source, schema, dependency, or lockfile change is present in this
   commit.
6. **Record the complete Stage 4 plan history — reviewed correction.** The
   approved plan was corrected three times during implementation — twice during
   Tasks 2 and 4, and once by the pre-Task-5 corrective landing — so recording only the
   original approval hash would misstate which document the stage was built
   against. Task 9 must record **all** relevant Stage 4 plan commits, in order:
   - the **original approved plan commit**
     `b6721b870c79db7b999b9eb70107e53992cbe1ab`;
   - the **Task 2 hash-material correction**
     `65eca5b17d45c0cf04f856dc6049e0c3ee7a2be9`
     (`docs: define stage 4 hash-material model types`);
   - **this Task 4 fixture-and-diagnostic correction commit**
     (`docs: resolve stage 4 fixture and diagnostic bounds`), whose hash is read
     from Git after it lands, recorded in the ledger, **and recorded in the
     roadmap's Stage 4 row alongside the other two** — the ledger alone is not
     sufficient, because section 9.0 step 4 makes it git-ignored, so a
     ledger-only record would leave this correction in no committed artifact. The
     Stage 3 row is the precedent for recording a post-approval correction hash in
     the roadmap. It is deliberately named descriptively rather than by hash here,
     because a document cannot contain its own commit hash. It carries **four**
     reviewed changes:
     1. Task 4 fixture ownership — `invalid/feature_cycle.yaml` plus the six root
        golden inputs, with Task 2's glob narrowed for the future (sections 6.5.1
        and 6.5.3);
     2. the bounded-diagnostic contract and its single new error code
        `STRATEGY.DIAGNOSTIC_LIMIT_REACHED` (sections 5.4.1 and 5.9);
     3. the closed `future_reference` disposition, including the specification
        section 12.3.3 line 713 discharge (section 6.5.2);
     4. the rule that a detected feature cycle gates warm-up validation and
        topological ordering, which is the consequence that makes Task 4 step 2
        executable (Task 4, "a detected cycle gates warm-up and topological
        order").
   - **this pre-Task-5 reference-and-diagnostic correction commit**
     (`docs: close stage 4 reference and diagnostic gaps`), whose hash is likewise
     read from Git after it lands and recorded in **both** the ledger and the
     roadmap's Stage 4 row, for the same reason. Named descriptively rather than by
     hash because a document cannot contain its own commit hash. It carries
     **two** reviewed rulings:
     1. reference-namespace disjointness and its single new error code
        `STRATEGY.REFERENCE_NAMESPACE_COLLISION` (sections 5.10 and 5.9);
     2. Task 3 diagnostic bounding, which supersedes section 5.4.1's
        "separate scope ruling, not Task 4 work" paragraph on that one point
        (section 5.4.2).
   - any further reviewed plan-correction commit that lands before Task 9.

   **The complete Stage 4 plan-commit chain Task 9 must record is therefore four
   commits**, in order: `b6721b870c79db7b999b9eb70107e53992cbe1ab`,
   `65eca5b17d45c0cf04f856dc6049e0c3ee7a2be9`,
   `f898499d647d1d4ade571345973c6ced5e84403c`, and this one. The Stage 4
   implementation commit `2b8601fb3db4d43691586fd5253cb3473d5248a0`
   (`feat: add feature graph and level 1 evaluator`) is Task 4's, not a plan
   commit, and is recorded separately.

   The plan-approval guard's pinned corrected-plan hash still identifies the
   approval commit, not the corrections; Task 9 records the corrections alongside
   it rather than replacing it.

**Focused verification:**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\safety -q
```

**Broader:** the complete verifier `scripts/verify.ps1`, first-attempt pass.

**Security review:** confirm the commit changes exactly the roadmap and the
status guard, and that no implementation file is touched.

**Independent review gate:** required before commit.

**Commit:** `test: record project 1 stage 4 completion`

The whole-stage review follows Task 9.

### 9.8 Exact `_DEFERRED_DEFINITIONS` changes

Remove exactly these fourteen names, because Stage 4 defines each of them as a
`class` that the guard's `ClassDef | FunctionDef | AsyncFunctionDef` walk would
otherwise reject:

```text
ApproximationDeclaration   CapabilityDeclaration   CapabilityRequirement
CapabilityVocabulary       ComparisonEligibilityResult
ComparisonLevel            CompatibilityOutcome    CompatibilityPolicy
CompatibilityResolver      CompatibilityResult
RuntimeAvailabilityObservation
StrategyLoader             StrategySpec            StrategyVersion
```

`Result` is **kept** in `_DEFERRED_DEFINITIONS`. Appendix G defines it as
`type Result[T] = Annotated[...]`, which is an `ast.TypeAlias` node and is
therefore never inspected by the guard, while its `Success` and `Failure`
classes are not in the deferred set. Removing `Result` would silently weaken
the guard for later stages without being required. `CapabilityVocabulary` and
`CompatibilityResolver` must be implemented as classes for their removals to
be necessary; if either becomes a module-level function or constant instead,
leave its name deferred.

Keep every other name deferred. In particular
`ComparisonEligibilityService` remains deferred to Stage 9 per section 5.8,
and `ValidationOutcome`, `NegotiationResult`, `AdapterCatalog`, and every
protocol, artifact, lifecycle, and persistence name remain deferred to their
owning stage.

## 10. Generated-schema ownership

Stage 4 may change canonical schemas only for strategies, expressions,
capabilities, requirements, approximations, compatibility, and comparison.

- **Exact paths and `$id` values:** section 6.3.
- **Exact registry entries:** appended to `SCHEMA_DEFINITIONS` in the section
  6.3 order, after the existing eleven, each as
  `SchemaDefinition(PurePosixPath("<path>"), "<$id>", TypeAdapter(<Model>))`.
  The expression schema uses the discriminated-union `TypeAdapter`, following
  the `ARTIFACT_OWNER_ADAPTER` precedent.
- **Exact expected schema count:** 11 before, **20** after.
- **Generation order:** registry order; `render_schema_files` sorts on write and
  asserts path and identifier uniqueness.
- **Distribution contents:** the wheel receives one copy under
  `crypto_lab/schemas/` and the sdist one copy under `schemas/`, both
  byte-identical to the reviewed source, via the existing `force-include`. No
  build configuration change is required.
- **Clean regeneration command:**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 schema-generate-write
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 schema-generate-check
```

- **Stage 3 byte-identity proof:** Task 8 step 5, plus the `schema-generate-check`
  gate in Task 6 covering the `CapabilityName` relocation specifically.

No relational migration is created, permitted, or implied. Stage 4 adds no
SQLAlchemy, Alembic, or SQLite artifact.

## 11. Acceptance gates

Stage 4 is complete only when every item below has fresh offline evidence.

1. `scripts/verify.ps1` exits zero on the **first** attempt from a clean
   Stage 4 worktree, and again on merged local `main`. No pass-on-rerun.
2. Only the approved Windows symbolic-link privilege skip remains.
3. Branch coverage is at least 90 percent and within one point of the 93.64
   percent Stage 3 baseline.
4. `schema-generate-check` is clean and the registry contains exactly 20 files.
5. `schema-distribution` is clean.
6. The eleven Stage 3 schemas are byte-identical to `main`.
7. Ruff format and lint pass; strict mypy reports no issue.
8. The offline package build succeeds.
9. Golden Level 1 feature and signal series pass for every fixture.
10. Strategy hashes are provably independent of comments, whitespace, and key
    order, and provably sensitive to every material field and extension hash.
11. All four compatibility outcomes are proven with stable, complete,
    deduplicated, deterministically ordered reasons.
12. `runtime.live` is rejected by core policy before resolution.
13. Comparison eligibility and every ineligibility reason are explicit.
14. No majority vote, averaging, or synthetic combined return exists anywhere.
15. Every Stage 4 exclusion in section 5.1 holds, proven by
    `tests/safety/test_stage4_boundaries.py`.
16. GitNexus was not invoked; the manual source, reference, and diff fallback
    was used and recorded.
17. No package-manager network command ran outside an explicitly approved
    one-time acquisition, and no acquisition is cited as verification evidence.
18. The complete base-to-HEAD diff is reviewed and the worktree is clean and
    committed.
19. Nine tasks are committed in order, each with its own independent review.
    Task 8 carries the implementation acceptance and the implementation commit
    and writes nothing into the roadmap; Task 9 records Stage 4 completion
    against Task 8's committed hash, does not present its own hash as the
    implementation hash, and confirms Stage 5 remains not started.
20. Both execution prerequisites are ancestors of `main` — the launcher
    bootstrap correction `350fac49ff5b1db4ec62b60c7ade76580f9894dd` and the
    separate roadmap-and-guard commit carrying this plan's approval — the
    section 9.0 preflight passed with both `$LASTEXITCODE` checks clean, and
    the corrected launcher is unchanged by Stage 4.
21. The classifier of section 5.2.1 obtains no implicit type information from
    `event.tag`, the mapping-key contract of section 5.2.2 holds for every
    rejected shape, and `SourceName` rejects every path-shaped value in section
    5.2.3.

### 11.1 Flake regression gates

These targeted stability gates are preserved and must pass on two consecutive
clean runs:

- the owner-hash round-trip property in `tests/property/test_artifact_ownership.py`;
- the owner material-sensitivity test;
- the fresh-import probe;
- the new Stage 4 strategy-hash properties;
- the complete verifier.

Stage 4 must not add a **global** Hypothesis suppression, must not raise a
global deadline, and must not add a project-wide profile that weakens
shrinking. A Stage 4-local health-check suppression is permitted, and is the
single governing rule on the subject, only with all four of: a genuinely
meaningful property; measured evidence of the timing or filtering problem;
scope limited to the exact test through a per-test `@settings(...)`; and
explicit independent approval recorded in the ledger. This mirrors the existing
precedent at `tests/property/test_artifact_ownership.py` line 207, which
carries a narrowly scoped `HealthCheck.too_slow` suppression with a recorded
eleven-line justification at lines 196 to 206.

## 12. Review and direct-merge workflow

1. Execute tasks in order. Each task ends with its own independent review and a
   clean committed worktree.
2. After **Task 9**, run a fresh whole-stage independent review covering
   architecture compliance, interface consistency, stage scope, schema
   ownership, YAML security, supply-chain safety, determinism, property-test
   quality, flake resistance, and privacy and network boundaries. The
   whole-stage review follows the status commit, not the implementation commit,
   so it reviews the final recorded state of the stage.
3. Every finding records severity, exact file and section, evidence,
   consequence, and required correction. Resolve every Critical and Important
   finding and rerun the scoped review. The implementing context must not
   approve its own unresolved findings.
4. Review the complete `main..HEAD` diff.
5. Run the complete verifier from the Stage 4 worktree.
6. From the clean main checkout, confirm `main` has not moved, then integrate
   with a direct local fast-forward:

```powershell
git -C "C:\Users\59557\Documents\Projects\Crypto_Trading" `
  merge --ff-only project-1-stage-4-implementation
```

7. No merge commit, pull, fetch, push, rebase, squash, amend, or pull request.
8. Run the complete verifier on merged `main`; it must pass on the first
   attempt.
9. Retain the Stage 4 branch and worktree. Do not begin Stage 5.

## 13. Construction appendices

### Appendix A — `pyproject.toml` patch (Task 1)

```diff
 dependencies = [
   "pydantic>=2.12,<3",
+  "pyyaml>=6.0.3,<7",
 ]
```

```diff
 dev = [
   "hatchling>=1.27,<2",
   "hypothesis>=6.130,<7",
   "jsonschema>=4.23,<5",
   "mypy>=1.15,<2",
   "pytest>=8.3,<9",
   "pytest-cov>=6,<7",
   "ruff>=0.11,<1",
+  "types-pyyaml>=6.0.12,<7",
 ]
```

No other `pyproject.toml` change is authorized. In particular
`[tool.mypy].overrides` must remain exactly the single `jsonschema` entry, and
`--cov-fail-under` must remain `90`.

### Appendix B — `tests/safety/test_project_dependencies.py` patch (Task 1)

```diff
-_EXPECTED_RUNTIME_REQUIREMENTS = ("pydantic>=2.12,<3",)
+_EXPECTED_RUNTIME_REQUIREMENTS = (
+    "pydantic>=2.12,<3",
+    "pyyaml>=6.0.3,<7",
+)
 _EXPECTED_DEVELOPMENT_NAMES = {
     "hatchling",
     "hypothesis",
     "jsonschema",
     "mypy",
     "pytest",
     "pytest-cov",
     "ruff",
+    "types-pyyaml",
 }
```

### Appendix C — `tests/safety/test_stage3_boundaries.py` patches (Tasks 2 through 8; status guard in Task 9)

Add to `_ALLOWED_SOURCE_FILES`, preserving alphabetical order:

```text
"capabilities/comparison.py",
"capabilities/models.py",
"capabilities/policy.py",
"capabilities/resolver.py",
"capabilities/vocabulary.py",
"domain/capability_names.py",
"domain/capability_requirements.py",
"domain/comparison_levels.py",
"domain/descriptors.py",
"domain/results.py",
"strategy/evaluation.py",
"strategy/expressions.py",
"strategy/feature_graph.py",
"strategy/loader.py",
"strategy/models.py",
"strategy/validation.py",
"strategy/versioning.py",
"strategy/yaml_source.py",
```

Add to `_ALLOWED_IMPORT_ROOTS`. The merged set has exactly 17 roots. Section
5.2's bytes-only contract removes any need for `io`, so **four** are added,
taking the set to 21:

```text
"codecs",
"contextlib",
"copy",
"yaml",
```

`codecs` is needed for the BOM literals in section 5.2 item 3, `contextlib`
for the explicit `contextlib.closing` of section 5.2 item 12, and `copy` for
the `copy.deepcopy` that section 5.3.1 fixes as the single alias-expansion
mechanism. `copy` is not optional: the import guard walks function-local
`Import` and `ImportFrom` nodes too, so a deferred import would not escape it,
and no project-owned recursive copier is specified. `re` is **already** in the
merged allowlist, so section 5.2.3's compiled pattern adds nothing.
`test_source_imports_only_the_explicit_stage3_allowlist` walks every `Import`
and `ImportFrom` node, including function-local ones, so a deferred import
would not avoid this.

Remove from `_DEFERRED_DEFINITIONS` exactly the fourteen names in section 9.8.
`Result` stays deferred.

Change the registry-count assertion:

```diff
-    assert len(paths) == 11
+    assert len(paths) == 20
```

No Stage 4 task modifies the **Stage 3** assertions inside
`test_stage3_completion_status_is_exact`. Task 8 and Task 9 hold the narrow,
enumerated authority defined by the status-authority rule in section 3.9 over
the four Stage-4-dependent strings, and Task 9 additionally adds a Stage 4
completion guard and updates the Stage 4 plan-approval guard that the separate
roadmap-and-guard commit introduced. Neither touches the closed-world lists
above.

### Appendix D — `crypto_lab/domain/hashing.py` patch (Tasks 2 and 5)

```diff
 class HashingProfile(StrEnum):
     CONFIGURATION_AUDIT_V1 = "configuration-audit/v1"
     CONFIGURATION_MATERIAL_BASE_V1 = "configuration-material-base/v1"
     DATASET_METADATA_V1 = "dataset-metadata/v1"
     ARTIFACT_OWNER_V1 = "artifact-owner/v1"
+    DIAGNOSTIC_IDENTITY_V1 = "diagnostic-identity/v1"
+    STRATEGY_VERSION_V1 = "strategy-version/v1"
```

`DIAGNOSTIC_IDENTITY_V1` is added by **Task 2** and `STRATEGY_VERSION_V1` by
**Task 5**; the diff above shows the end state.

### Appendix E — `crypto_lab/adapters/descriptors.py` patch (Task 6)

Delete every relocated definition and import it from `domain` instead, keeping
all names importable from this module so no existing import site changes:

```text
+from crypto_lab.domain.capability_names import CapabilityName, VocabularyVersion
+from crypto_lab.domain.descriptors import (
+    AdapterDescriptor,
+    EngineDescriptor,
+    OperatingSystem,
+    SupportedSchemaVersion,
+)

-class EngineDescriptor(CanonicalModel): ...
-class SupportedSchemaVersion(CanonicalModel): ...
-class AdapterDescriptor(CanonicalModel): ...
-class OperatingSystem(StrEnum): ...
-CapabilityName = Annotated[...]
-VocabularyVersion = Annotated[...]

+__all__ = [
+    "AdapterDescriptor",
+    "BoundedText",
+    "CapabilityName",
+    "EngineDescriptor",
+    "OperatingSystem",
+    "SupportedSchemaVersion",
+    "VocabularyVersion",
+]
```

The private module helpers `_unique_sorted_text`, `_unique_sorted_versions`,
`_set_unique_items`, **`_engine_schema_extra`, and `_descriptor_schema_extra`**
move **with** the classes into `crypto_lab/domain/descriptors.py`. This is
mandatory, not tidiness: if any stayed behind, `domain/descriptors.py` would
have to import from `crypto_lab.adapters.descriptors`, and
`crypto_lab.adapters` is in `_PROHIBITED_PROJECT_PACKAGES` for
`test_repository_domain_package_has_no_prohibited_imports` in
`tests/architecture/test_domain_import_boundary.py`. That would re-introduce
the exact dependency-direction violation section 5.7 exists to remove, through
the back door. The two `json_schema_extra` hooks are referenced from both
relocating classes' `model_config` and are easy to overlook.

**`BoundedText` is defined locally in `crypto_lab/domain/descriptors.py`**, not
imported from `adapters`, for the same reason: `EngineDescriptor.planned_role`,
`EngineDescriptor.known_limitations`, `AdapterDescriptor.runtime_requirements`,
and `AdapterDescriptor.known_modeling_limitations` all use it. A local
definition matches existing repository precedent — `configuration/models.py`
and `datasets/models.py` already carry independent local `BoundedText`
definitions — and nothing outside `adapters/descriptors.py` imports the
adapters copy. Add `BoundedText` to the `__all__` re-export as well, otherwise
the "public surface is unchanged" claim in sections 1.2 and 6.2 is false.

Every relocated class, annotation, and helper must be moved **verbatim**,
including `StringConstraints` bounds, validators, `json_schema_extra` hooks, and
the `exact_string_schema` calls. The generated
`schemas/protocol/adapter-descriptor-v1.schema.json` keys its `$defs` by bare
class and alias names, never by module path, and the capability annotations are
inlined with no `$def`, so a verbatim move cannot change the emitted bytes.
Task 6 step 12 keeps `schema-generate-check` as the blocking proof.

Note that `crypto_lab/adapters/versioning.py` and every other consumer keep
importing from `crypto_lab.adapters.descriptors` unchanged.

### Appendix F — `crypto_lab/schema_registry.py` patch (Task 8)

```diff
-from crypto_lab.adapters.descriptors import AdapterDescriptor, EngineDescriptor
+from crypto_lab.domain.descriptors import (
+    AdapterDescriptor,
+    EngineDescriptor,
+    RuntimeAvailabilityObservation,
+)
 from crypto_lab.artifacts.ownership import ARTIFACT_OWNER_ADAPTER
+from crypto_lab.capabilities.comparison import ComparisonEligibilityResult
+from crypto_lab.capabilities.models import (
+    ApproximationDeclaration,
+    CapabilityDeclaration,
+    CapabilityRequirement,
+    CompatibilityResult,
+)
 from crypto_lab.configuration.models import ApplicationConfig
 from crypto_lab.datasets.models import DatasetDescriptor, DatasetPartition
+from crypto_lab.strategy.expressions import EXPRESSION_ADAPTER
+from crypto_lab.strategy.models import StrategySpec
+from crypto_lab.strategy.versioning import StrategyVersion
```

Append, after the existing eleven entries. This block is a tuple-element
fragment, not a module, so it is fenced as `text`: `ruff format --check`
formats fenced ` ```python ` blocks inside Markdown, and a bare parenthesised
fragment would be rewritten. Keeping every `python` fence in this document
ruff-clean is what allows the plan to be committed without adding it to
`[tool.ruff] extend-exclude`, which Appendix A forbids.

```text
    SchemaDefinition(
        PurePosixPath("strategy/strategy-spec-v1.schema.json"),
        "urn:crypto-lab:schema:strategy:strategy-spec:1.0.0",
        TypeAdapter(StrategySpec),
    ),
    SchemaDefinition(
        PurePosixPath("strategy/strategy-version-v1.schema.json"),
        "urn:crypto-lab:schema:strategy:strategy-version:1.0.0",
        TypeAdapter(StrategyVersion),
    ),
    SchemaDefinition(
        PurePosixPath("strategy/expression-v1.schema.json"),
        "urn:crypto-lab:schema:strategy:expression:1.0.0",
        EXPRESSION_ADAPTER,
    ),
    SchemaDefinition(
        PurePosixPath("capabilities/capability-requirement-v1.schema.json"),
        "urn:crypto-lab:schema:capabilities:capability-requirement:1.0.0",
        TypeAdapter(CapabilityRequirement),
    ),
    SchemaDefinition(
        PurePosixPath("capabilities/capability-declaration-v1.schema.json"),
        "urn:crypto-lab:schema:capabilities:capability-declaration:1.0.0",
        TypeAdapter(CapabilityDeclaration),
    ),
    SchemaDefinition(
        PurePosixPath("capabilities/approximation-declaration-v1.schema.json"),
        "urn:crypto-lab:schema:capabilities:approximation-declaration:1.0.0",
        TypeAdapter(ApproximationDeclaration),
    ),
    SchemaDefinition(
        PurePosixPath("capabilities/compatibility-result-v1.schema.json"),
        "urn:crypto-lab:schema:capabilities:compatibility-result:1.0.0",
        TypeAdapter(CompatibilityResult),
    ),
    SchemaDefinition(
        PurePosixPath("capabilities/runtime-availability-observation-v1.schema.json"),
        "urn:crypto-lab:schema:capabilities:runtime-availability-observation:1.0.0",
        TypeAdapter(RuntimeAvailabilityObservation),
    ),
    SchemaDefinition(
        PurePosixPath("capabilities/comparison-eligibility-result-v1.schema.json"),
        "urn:crypto-lab:schema:capabilities:comparison-eligibility-result:1.0.0",
        TypeAdapter(ComparisonEligibilityResult),
    ),
```

Note that `schema_registry.py` may import from `strategy` and `capabilities`
because it is a composition-style module outside the layered packages, exactly
as it already imports from `adapters`, `artifacts`, `configuration`,
`datasets`, and `domain`.

### Appendix G — `Result` construction sketch (Task 2)

```python
class Success(CanonicalModel, Generic[T]):
    outcome: Literal["SUCCESS"]
    value: T


class Failure(CanonicalModel):
    outcome: Literal["FAILURE"]
    diagnostics: tuple[Diagnostic, ...] = Field(min_length=1, max_length=256)


type Result[T] = Annotated[Success[T] | Failure, Field(discriminator="outcome")]
```

`Failure` requires at least one diagnostic, so a failure can never be empty,
and `Success` carries no diagnostics, so the two cannot be confused. Expected
boundary failures are communicated through `Result`, never through exceptions
alone.

### Appendix H — bounded event-scan sketch (Task 2)

This appendix is normative for shape and check ordering. It must agree with
sections 5.2 and 5.3 exactly: the input is a decoded `str`, there is exactly
**one** pass, the value is built during that pass, and alias cost is
**transitive**.

```python
def _build_document(text: str, source_name: SourceName) -> Result[YamlDocument]:
    budget = _Budget()
    events = yaml.parse(text, Loader=StrictStrategySafeLoader)
    with contextlib.closing(events):
        return _build_from_events(iter(events), budget, source_name)
```

`_Budget` carries `events`, `expanded`, `alias_references`,
`anchor_definitions`, a `dict[str, int]` of completed anchor **expanded**
sizes, a `dict[str, object]` of completed anchor **values** for deep-copy
expansion, and a stack of open anchor frames. There is **no** recorded event
subsequence and no replay: section 5.3.1 fixes deep-copy of the built value as
the single expansion mechanism, precisely so an alias cannot be charged twice.
Its `charge` method is where the expanded-node ceiling is enforced:

```python
def charge(self, cost: int, open_frames: list[_Frame]) -> str | None:
    self.expanded += cost
    for frame in open_frames:
        frame.cost += cost
    if self.expanded > MAX_EXPANDED_NODES:
        return "STRATEGY.YAML_EXPANSION_EXCEEDED"
    return None
```

Required behaviour, all of which the Task 2 tests fix precisely:

1. Every node-producing event — `ScalarEvent`, `SequenceStartEvent`,
   `MappingStartEvent` — charges `1`; framing and collection-end events charge
   nothing, per section 5.3.1. Every alias event charges the target
   anchor's recorded **expanded** size, so nested anchors compound and the
   nine-level bomb is rejected. Charging a raw subtree event count instead
   would let that bomb pass every ceiling. The deep-copied value spliced in at
   the alias site is **not** charged again — the alias site already paid for
   the whole node. `charge` is the single place `MAX_EXPANDED_NODES` is
   enforced; the other ceilings — `MAX_EVENT_COUNT`, `MAX_ANCHORS`,
   `MAX_ALIAS_REFERENCES`, `MAX_SCALAR_CHARACTERS`, `MAX_COLLECTION_ENTRIES`,
   and both depth counters — are structurally not chargeable there and are
   enforced at their own event sites.
2. `charge` is called before the event is consumed, so rejection happens
   mid-stream.
3. An alias whose anchor frame is still open, or whose name was never defined,
   is rejected with `STRATEGY.YAML_RECURSIVE_ALIAS`. This makes a cyclic value
   structurally impossible rather than test-enforced.
4. Redefining an anchor name is rejected with
   `STRATEGY.YAML_ANCHOR_REDEFINED`; `anchor_definitions` counts definitions,
   not distinct names.
5. Two independent depth counters are maintained: `MAX_EVENT_DEPTH` over the
   event stream and `MAX_EXPANDED_DEPTH` over the value being built. Alias
   expansion increases the second without increasing the first, so both are
   required.
6. A second `DocumentStartEvent` is rejected with
   `STRATEGY.YAML_MULTIPLE_DOCUMENTS`; a stream with none is rejected with
   `STRATEGY.YAML_EMPTY_DOCUMENT`.
7. The builder returns the bounded plain value directly. `yaml.compose`,
   `yaml.compose_all`, and the Constructor are never called, so there is no
   second pass, no rewind, no shared node graph, and no scan-versus-build
   divergence.

### Appendix I — `tests/unit/test_schema_registry.py` patch (Task 8)

This file is a **second** closed-world schema guard, independent of
`tests/safety/test_stage3_boundaries.py`, and Task 8 fails without it. It
contains a literal 11-entry `_EXPECTED` map from relative path to `$id`, plus
`assert len(SCHEMA_DEFINITIONS) == 11`, a set comparison against `_EXPECTED`,
and a per-path `schema["$id"] == _EXPECTED[path]` lookup that raises `KeyError`
for any unlisted path. The test function is named
`test_registry_has_exactly_the_closed_eleven_paths_and_ids`.

Required changes:

1. Add the nine section 6.3 path-to-`$id` pairs to `_EXPECTED`, preserving its
   existing ordering convention.
2. Change `assert len(SCHEMA_DEFINITIONS) == 11` to `== 20`.
3. Rename the function to
   `test_registry_has_exactly_the_closed_twenty_paths_and_ids`.

**Expected RED before the registry change:** `AssertionError: assert 11 == 20`.

### Appendix J — `tests/unit/test_package_layout.py` patch (Task 2 onward)

`PACKAGE_MODULES` is a positive module list that drives the fresh-import probe
named in section 11.1. Nothing compares it to the filesystem, so omitting a
module weakens coverage rather than failing a test; each task nevertheless
appends the modules it creates, starting with Task 2. To make that instruction
executable rather than aspirational, `tests/unit/test_package_layout.py` is in
the Files list of **every task from Task 2 through Task 8** that creates a
source module.

**What the probe actually asserts.** `_IMPORT_PROBE` patches `builtins.open`,
`os.putenv`/`unsetenv`/`system`/`spawn*`/`startfile`, `socket`, `subprocess`,
`urllib`, `http.client`, `winreg`, and seventeen `pathlib.Path` methods
(`home`, `expanduser`, `open`, `read_bytes`, `read_text`, `exists`, `is_dir`,
`is_file`, `iterdir`, `glob`, `rglob`, `stat`, `lstat`, `mkdir`, `touch`,
`write_bytes`, `write_text`). It does **not**
patch `io.open_code`, `_io.FileIO`, `os.stat`, or `_imp.create_dynamic`, which
is what the import machinery and extension loading actually use. So the probe
asserts "no `builtins.open`, `pathlib`, socket, subprocess, or registry side
effect during import" — **not** "no file read". It has zero observational power
over the loading of `yaml._yaml.cp312-win_amd64.pyd`, and the plan must not
claim otherwise.

Task 2 must nevertheless prove that importing `crypto_lab.strategy.yaml_source`
— and therefore `yaml` — survives the probe as it exists.

**Importing `yaml` is not pure Python.** PyYAML's package initializer
`yaml/__init__.py` attempts `from .cyaml import *` inside a `try` / `except
ImportError`, setting `__with_libyaml__` accordingly, and `yaml/cyaml.py`
imports `CParser` and `CEmitter` from the compiled extension `yaml._yaml`. The
selected `pyyaml-6.0.3-cp312-cp312-win_amd64.whl` ships that extension, so
importing `yaml` loads a compiled module. Therefore:

- importing `yaml` may load its optional compiled extension, and on the
  selected Windows wheel it does;
- **Stage 4 never selects `CLoader`, `CSafeLoader`, `CParser`, `CBaseLoader`,
  `CFullLoader`, `CUnsafeLoader`, or any other C parsing surface.** The Task 1
  AST guard forbids all of those names, plus `cyaml` and `_yaml`, anywhere
  under `src/crypto_lab`;
- actual strategy parsing uses the reviewed Python `SafeLoader` subclass
  `StrictStrategySafeLoader`, whose membership in `yaml.SafeLoader.__mro__` is
  asserted by a Task 2 test, so the pure-Python Scanner and Parser that every
  safety argument in section 5 reasons about are the ones that run;
- the fresh-import probe remains authoritative for the import effects it can
  observe, which are enumerated in Appendix J and do **not** include the
  compiled extension's load. It is a measurement, not a claim: if it fails, the
  correct fix is a deferred function-local `import yaml` inside
  `load_yaml_document`, **not** a weakened probe. Record the measured outcome
  in the ledger either way. The controls that actually bound the C surface are
  the qualified AST name ban of Task 1 and the
  `yaml.SafeLoader in StrictStrategySafeLoader.__mro__` pin of Task 2, not the
  probe.

## 14. Plan self-review

- Every task states exact files, consumed and produced interfaces, a test-first
  sequence with an expected RED, a minimum GREEN, focused and broader
  verification, Ruff, strict mypy, schema checks where applicable, a security
  review, an independent review gate, an exact commit message, and a clean
  task boundary.
- The YAML choice is resolved to exactly one package and one bounded range.
- Every bound the library does not provide publicly is project-owned and
  reviewable.
- The closed-world Stage 3 guards are named with exact patches.
- Schema ownership names exact paths, identifiers, registry entries, the exact
  count change from 11 to 20, and the Stage 3 byte-identity proof.
- Two decisions are explicitly escalated rather than assumed: the section 5.7
  dependency direction and the section 5.8 Stage 4 / Stage 9
  comparison-service boundary.
- No placeholder, no "as needed" instruction, and no unresolved choice remains.

### 14.1 Corrections applied after the first independent review

1. **Launcher bootstrap.** Section 3.8 replaced the claim that every profile
   requires an existing project environment. Five uv bootstrap profiles now
   reach uv without the project interpreter, `sync` is the supported
   fresh-worktree bootstrap, and no direct `uv` command is needed. Recorded as
   execution prerequisite `350fac49ff5b1db4ec62b60c7ade76580f9894dd`.
2. **YAML event resolution.** Section 5.2 item 7 no longer claims parse events
   carry resolved implicit tags. Section 5.2.1 records the PyYAML 6.0.3 parser,
   composer, resolver, and scanner evidence and defines a project-owned
   classifier that never reads an implicit type from `event.tag`.
3. **Mapping keys.** Section 5.2.2 adds the string-only mapping-key contract and
   the new error code `STRATEGY.YAML_MAPPING_KEY_INVALID`.
4. **`SourceName`.** Section 5.2.3 corrects the pattern to
   `^(?!.*\.\.)[a-z0-9][a-z0-9._-]{0,127}$`, keeps the length bound, and fixes
   the declaration mechanism, because Pydantic's default `rust-regex` engine
   cannot compile look-around.
5. **Task 1 RED.** Three meaningful REDs replace the fabricated
   "file does not exist" claims, and the source guardrails expected to begin
   green are classified as preventive safety tests.
6. **PyYAML import.** Appendix J replaces the pure-Python import claim with the
   `yaml/__init__.py` compiled-extension evidence and its consequences.
7. **Status task.** The stage is nine tasks. Task 8 owns implementation
   acceptance and must not write its own hash into the roadmap; Task 9 owns the
   completion status and its executable guard.
