# Project 1 Portable Strategy, Capabilities, and Comparison Implementation Plan

**Status:** Detailed Stage 4 implementation plan awaiting independent review
**Stage:** 4 of 10
**Planning base commit:** `e1c821453459f5eccf86a472e9204b6a90829d64`
**Date:** 2026-08-10

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
    comparison levels, capability names, Result)
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

- `scripts/invoke-uv.ps1` resolves `.venv\Scripts\python.exe` **before** the
  operation switch, so every profile requires an existing project environment.
  Closed profiles: `lock-check`, `lock-resolve-offline`, `sync`,
  `lock-acquire`, `sync-acquire`, `ruff-format-all`, `ruff-check-all`,
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
| `_ALLOWED_SOURCE_FILES` | 33 exact relative paths | Add every new `strategy/*.py`, `capabilities/*.py`, and `domain/*.py` file |
| `_ALLOWED_IMPORT_ROOTS` | 17 roots | Add `codecs`, `contextlib`, and `yaml`. The bytes-only contract of section 5.2 removes any need for `io`, but items 3 and 12 of that section require the first two |
| `_DEFERRED_DEFINITIONS` | 79 names | Remove exactly the names Stage 4 defines (section 9.8) |
| `test_schema_registry_is_closed_and_protocol_descriptors_are_located_correctly` | `assert len(paths) == 11` | Change to `20` |
| `test_stage3_completion_status_is_exact` | Pins roadmap Stage 3 row text | Leave unchanged by Stage 4; owned by the separate roadmap-status repair |

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
constructor registration. The compensating control is that Task 1 forbids the
libyaml surface by name and pins `yaml.SafeLoader` in the loader's MRO, so a
future change cannot silently route through `CSafeLoader` and invalidate that
reasoning.

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

It must, in this exact order:

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
7. Accept only the resolved tags `tag:yaml.org,2002:map`, `:seq`, `:str`,
   `:int`, `:bool`, and `:null`. Every other tag — including `:float`,
   `:timestamp`, `:binary`, `:set`, `:omap`, `:merge`, every `!!python/...`
   form, and every unknown custom tag — is rejected with
   `STRATEGY.YAML_FORBIDDEN_TAG`. Floats are rejected outright so that
   authoritative numeric values reach Pydantic only as canonical decimal
   strings or integers.
8. Re-validate the **raw scalar text** of every implicitly resolved scalar, not
   merely its resolved tag. PyYAML's `SafeLoader` applies YAML 1.1 implicit
   resolution, under which `010` resolves to `8`, `1_000` to `1000`, `0x20` to
   `32`, `12:30` to `750`, and `no`/`off`/`n` to `False`. Silently accepting
   those would write a value the author never expressed into a permanent
   `content_hash`. Therefore:
   - `:int` is accepted only when `ScalarNode`-equivalent style is plain and
     the text matches `^-?(0|[1-9][0-9]*)$`;
   - `:bool` is accepted only for exactly `true` or `false`;
   - `:null` is accepted only where a field's declared type is an explicit
     nullable union; the bare empty plain scalar is always rejected. Because
     the repository uses `MISSING`, never `None`, for absence, `strategy/v1`
     declares no nullable field, so in practice every `:null` is rejected with
     `STRATEGY.YAML_NONCANONICAL_SCALAR`. Omit the key instead.
   Every other form is rejected with `STRATEGY.YAML_NONCANONICAL_SCALAR`. Tests
   cover `010`, `1_000`, `12:30`, `0x20`, `+1`, `yes`, `no`, `on`, `off`, `y`,
   `n`, their case variants, and the empty value.
9. Reject duplicate mapping keys deterministically **before** any mapping value
   is materialised, reporting the first duplicate in document order with its
   key and its line and column. There is no code path that produces a `dict`
   without this check having run. PyYAML's own behaviour is silent last-wins,
   so this control is the only thing standing between a duplicated key and a
   silently wrong permanent hash.
10. Reject the `<<` merge key unconditionally in `strategy/v1`. Merge semantics
    would make canonical content depend on resolution order and are
    unnecessary for version 1.
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
13. Hand off to Pydantic in **JSON mode**. The bounded plain value is
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
    `Mark.buffer`, or `Mark.name`. Only the integer `line` and `column` from a
    `Mark`, plus a fixed project-authored message per error code, may enter a
    diagnostic. A test asserts that a syntax-error diagnostic contains none of
    the document's distinctive tokens.

`SourceName` is a constrained type declared with `exact_string_schema` and the
pattern `^[a-z0-9][a-z0-9._-]{0,127}$`, which forbids `/`, `\`, `:`, `..`, and
a leading `~`. It is a label, never a filesystem path. Tests reject
`C:\x\y.yaml`, `../x.yaml`, and `//host/share/x.yaml`. This matters because
`StrategySourceProvenance` retains `source_name` for audit, and specification
section 24.3 requires diagnostics and audit details to be redacted; a raw path
would leak a local username.

Typing note: typeshed annotates PyYAML node and event `value` attributes as
`Any`. `disallow_any_expr` is not part of mypy `strict`, so the builder must
narrow with `isinstance` rather than assigning through an `Any`.

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

#### 5.3.1 Transitive alias-expansion accounting

A raw per-anchor event count is **not** sufficient, because it does not include
the expansion of aliases nested inside that anchor. Nine levels of
`&L[n] [*L[n-1] x9]` is roughly 100 raw events, 81 alias references, 9 anchor
definitions, and depth 2 — inside every raw ceiling — yet denotes about
`9**9` values. Accounting must therefore be **transitive**:

- maintain a stack of open anchor frames, each with a `cost` counter;
- on every non-alias event, add `1` to `expanded` and to every open frame's
  `cost`;
- on an alias event, look up `expanded_size[name]`; reject with
  `STRATEGY.YAML_RECURSIVE_ALIAS` if the name is unknown or its frame is still
  open; otherwise add that recorded **expanded** cost to `expanded` and to
  every open frame's `cost`;
- check `expanded > MAX_EXPANDED_NODES` immediately after every update and
  reject with `STRATEGY.YAML_EXPANSION_EXCEEDED`;
- when an anchor's node closes, record `expanded_size[name] = frame.cost`, and
  reject if that cost alone exceeds `MAX_EXPANDED_NODES`.

Because the value is built in the same pass, `expanded` is an exact count of
the nodes the builder will materialise, and the expanded-depth counter bounds
the builder's own recursion. `MAX_EXPANDED_NODES` at 50,000 keeps the builder
far below Python's recursion and memory limits.

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
2. rejection occurs during the single pass, proven by asserting that
   `yaml.compose`, `yaml.compose_all`, `yaml.load`, and `yaml.safe_load` are
   never called — the Task 1 source guard already forbids naming them;
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
   payload))`, where `payload` is the diagnostic's material content
   (`error_code`, `category`, `severity`, `source_component`, `message`,
   `details`, and any correlation IDs). `_uuid4_shaped` takes the first 32 hex
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
6. `crypto_lab.capabilities` imports **nothing** from `crypto_lab.adapters`.
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

### 5.8 Stage 4 / Stage 5 comparison boundary

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
STRATEGY.YAML_SYNTAX                 STRATEGY.YAML_MULTIPLE_DOCUMENTS
STRATEGY.YAML_EMPTY_DOCUMENT         STRATEGY.YAML_FORBIDDEN_TAG
STRATEGY.YAML_DUPLICATE_KEY          STRATEGY.YAML_MERGE_KEY_FORBIDDEN
STRATEGY.YAML_SCALAR_TOO_LONG        STRATEGY.YAML_COLLECTION_TOO_LARGE
STRATEGY.YAML_DEPTH_EXCEEDED         STRATEGY.YAML_EVENT_BUDGET_EXCEEDED
STRATEGY.YAML_ANCHOR_BUDGET_EXCEEDED STRATEGY.YAML_ALIAS_BUDGET_EXCEEDED
STRATEGY.YAML_EXPANSION_EXCEEDED     STRATEGY.YAML_RECURSIVE_ALIAS
STRATEGY.YAML_NONCANONICAL_SCALAR    STRATEGY.YAML_ANCHOR_REDEFINED
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
STRATEGY.EVALUATION_MISSING_INPUT
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

## 6. Exact Stage 4 file map

### 6.1 New source files

| Path | Responsibility |
|---|---|
| `src/crypto_lab/domain/results.py` | `Result[T]` discriminated success-or-diagnostics value, `Success`, `Failure`, helpers |
| `src/crypto_lab/domain/capability_names.py` | `CapabilityName`, `VocabularyVersion` relocated from `adapters/descriptors.py` |
| `src/crypto_lab/domain/descriptors.py` | `EngineDescriptor`, `AdapterDescriptor`, `SupportedSchemaVersion`, `OperatingSystem` relocated from `adapters/descriptors.py`; new `RuntimeAvailabilityObservation` |
| `src/crypto_lab/domain/comparison_levels.py` | `ComparisonLevel`, kept in `domain` so Stage 6's `EngineRunRequest` never needs an `adapters -> capabilities` edge |
| `src/crypto_lab/strategy/yaml_source.py` | Safe YAML loading and the single-pass bounded event-to-value builder of sections 5.2 and 5.3; no node graph is ever composed |
| `src/crypto_lab/strategy/expressions.py` | Closed discriminated expression AST |
| `src/crypto_lab/strategy/models.py` | `StrategySpec` and every sub-model |
| `src/crypto_lab/strategy/feature_graph.py` | DAG validation, cycle diagnostics, stable topological order |
| `src/crypto_lab/strategy/validation.py` | Static expression type checking and reference validation |
| `src/crypto_lab/strategy/evaluation.py` | Deterministic Level 1 reference evaluator |
| `src/crypto_lab/strategy/versioning.py` | `StrategyVersion`, provenance, extension declarations, hashing |
| `src/crypto_lab/strategy/loader.py` | `StrategyLoader` facade returning `Result[StrategyVersion]` |
| `src/crypto_lab/capabilities/vocabulary.py` | `capabilities/v1` closed vocabulary |
| `src/crypto_lab/capabilities/models.py` | Requirement, declaration, approximation, availability, result models |
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
| `tests/unit/strategy/test_strategy_yaml_source.py` | Loader contract, tags, duplicate keys, merge keys, documents, encoding |
| `tests/unit/strategy/test_strategy_yaml_bounds.py` | Every bound in section 5.3, including alias expansion |
| `tests/unit/strategy/test_strategy_expressions.py` | Every AST node, arity, discriminator closure |
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
| `tests/unit/domain/test_domain_descriptors.py` | Relocated descriptors and `RuntimeAvailabilityObservation` |
| `tests/property/test_strategy_hashing.py` | Formatting independence, material sensitivity |
| `tests/property/test_compatibility_resolution.py` | Order-independence, reason stability |
| `tests/property/test_expression_evaluation.py` | Decimal and missing-value invariants |
| `tests/safety/test_stage4_boundaries.py` | Forbidden YAML API names, import closure, no global mutation |
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
invalid/future_reference.yaml             invalid/python_tag.yaml
invalid/unknown_tag.yaml                  invalid/duplicate_key.yaml
invalid/merge_key.yaml                    invalid/two_documents.yaml
invalid/billion_laughs.yaml               invalid/deep_nesting.yaml
invalid/recursive_alias.yaml              invalid/feature_cycle.yaml
invalid/unknown_operation.yaml            invalid/type_mismatch.yaml
```

`sma_cross_long.valid.yaml`, `sma_cross_long.reordered_keys.yaml`, and
`sma_cross_long.commented.yaml` differ only in comments, whitespace, and
mapping key order, and must produce an identical `content_hash`.

### 6.6 Modified test and documentation files

| Path | Change |
|---|---|
| `tests/safety/test_stage3_boundaries.py` | `_ALLOWED_SOURCE_FILES`, `_ALLOWED_IMPORT_ROOTS`, `_DEFERRED_DEFINITIONS`, schema count `11` to `20` |
| `tests/safety/test_project_dependencies.py` | `_EXPECTED_RUNTIME_REQUIREMENTS`, `_EXPECTED_DEVELOPMENT_NAMES`, pinned mypy table keys |
| `tests/unit/test_schema_registry.py` | Closed 11-entry `_EXPECTED` path-to-`$id` map, `len(SCHEMA_DEFINITIONS) == 11`, and the test name (Appendix I) |
| `tests/unit/test_package_layout.py` | Closed `PACKAGE_MODULES` list, which drives the fresh-import probe |
| `pyproject.toml` | Add `pyyaml>=6.0.3,<7`; add `types-pyyaml>=6.0.12,<7` to `dev` |
| `uv.lock` | Regenerated by the launcher; never hand-edited |
| `docs/development/verification.md` | Stage 4 focused checks and schema count |
| `README.md` | Status line and strategy-loading summary |
| `docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md` | Stage 4 implementation status at completion |

Stage 4 must not modify `scripts/invoke-uv.ps1`, `scripts/verify.ps1`,
`scripts/generate_schemas.py`, `scripts/verify_schema_distribution.py`, or
`tests/safety/test_uv_launcher.py`.

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

Eight separately reviewable tasks. No task may be merged into another, and each
ends in a clean committed worktree.

**Closed-world guard rule.** `tests/safety/test_stage3_boundaries.py` is in the
Files list of **every** task from Task 2 onward, and each task applies only the
subset of Appendix C matching the files and deferred names it actually creates.
This is mandatory because `test_stage3_source_file_set_is_closed` asserts exact
set equality against the real filesystem: a task that adds a source file
without extending `_ALLOWED_SOURCE_FILES` fails, and a task that adds the whole
Appendix C list up front also fails, because the allowlist would then name
files that do not yet exist. `_DEFERRED_DEFINITIONS` removals follow the same
rule — remove a name in the task that defines it, never earlier.
`_ALLOWED_IMPORT_ROOTS` is membership-only, so its three additions may be made
once in Task 2.

**Task 2 additionally owns `strategy/expressions.py`.** `StrategySpec` declares
`entry_rules` and `exit_rules` as expression trees, so the model cannot be
defined without the AST, and the source-file guard forbids Task 2 from creating
a file Task 3 owns. Task 2 therefore defines the closed AST node models; Task 3
owns `validation.py`, the static type and reference checking, and the exhaustive
per-node tests.

### Task 1 — YAML dependency, lock gates, and security tests

**Files:** `pyproject.toml`, `uv.lock`, `tests/safety/test_project_dependencies.py`,
`tests/safety/test_stage4_boundaries.py` (new).

**Consumes:** the Stage 3 launcher profiles and dependency guards.
**Produces:** an installed, locked, typed `yaml` import root and the Stage 4
source-level security guard.

**Test-first sequence**

1. Add to `tests/safety/test_stage4_boundaries.py` an AST test asserting that
   no file under `src/crypto_lab` references any of these **names**, whether as
   a call, an attribute, or an assignment target:
   `yaml.load`, `yaml.full_load`, `yaml.unsafe_load`, `yaml.safe_load`,
   `yaml.compose`, `yaml.compose_all`, `Loader`, `FullLoader`, `UnsafeLoader`,
   `CLoader`, `CFullLoader`, `CUnsafeLoader`, `CSafeLoader`, `CBaseLoader`,
   `CParser`, `cyaml`, `_yaml`, `YAMLObject`, `add_constructor`,
   `add_multi_constructor`, `add_implicit_resolver`, `yaml_constructors`,
   `yaml_multi_constructors`, `yaml_implicit_resolvers`.
   The three attribute names matter independently of the `add_*` methods,
   because `StrictStrategySafeLoader.yaml_constructors[t] = f` mutates the
   inherited `yaml.SafeLoader` dict. Matching is on exact `ast.Name.id`,
   `ast.Attribute.attr`, and assignment targets — never on substrings, and
   never on `ast.keyword.arg`, so the required
   `Loader=StrictStrategySafeLoader` keyword does not self-collide with the
   banned bare name `Loader`.
   **Expected RED:** the test file does not exist, so collection fails.
2. Add the **absolute** part of the global-state test that does not depend on
   Stage 4 code: assert
   `frozenset(yaml.SafeLoader.yaml_constructors) == _EXPECTED_SAFELOADER_TAGS`
   against a tag set pinned literally in the test file. This holds at import
   time and catches a third-party `yaml.YAMLObject` registration. A
   before/after-load comparison is structurally incapable of detecting
   class-body or import-time mutation, which is why the assertion is absolute.
   **Expected RED:** module missing.
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
4. Extend `test_mypy_untyped_import_override_is_exact` to assert
   `set(mypy) == {"python_version", "strict", "files", "overrides"}`. The
   existing assertion pins only `overrides`, so a top-level
   `ignore_missing_imports = true` or `disable_error_code = [...]` would relax
   typing repository-wide while leaving the test green.
5. Add a test asserting `_EXPECTED_RUNTIME_REQUIREMENTS == ("pydantic>=2.12,<3",
   "pyyaml>=6.0.3,<7")` and that `_EXPECTED_DEVELOPMENT_NAMES` contains
   `types-pyyaml`. **Expected RED:**
   `AssertionError` comparing the current one-element tuple.
6. Add a lock test asserting that `uv.lock` contains a `types-pyyaml` package —
   so a silent stub-less install is caught — and that the locked `pyyaml`
   package has a `wheels` entry matching `cp312` and `win_amd64`. The existing
   `test_lock_registry_artifacts_are_sha256_pinned` does not distinguish sdist
   from wheel, and `no-build-isolation = true` means an sdist path would run
   PyYAML's `setup.py` against the project environment.
7. Update `pyproject.toml` to add `"pyyaml>=6.0.3,<7"` to
   `[project].dependencies` and `"types-pyyaml>=6.0.12,<7"` to
   `[dependency-groups].dev`.
8. Run the section 8 dependency flow.
9. Update `_EXPECTED_RUNTIME_REQUIREMENTS` and `_EXPECTED_DEVELOPMENT_NAMES`
   to the new exact values.

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
`src/crypto_lab/domain/hashing.py` (adds `DIAGNOSTIC_IDENTITY_V1` and
`_uuid4_shaped` only), `src/crypto_lab/strategy/yaml_source.py`,
`src/crypto_lab/strategy/expressions.py`,
`src/crypto_lab/strategy/models.py`,
`tests/unit/domain/test_domain_results.py`,
`tests/unit/domain/test_domain_descriptors.py`,
`tests/unit/strategy/test_strategy_yaml_source.py`,
`tests/unit/strategy/test_strategy_yaml_bounds.py`,
`tests/unit/strategy/test_strategy_models.py`,
`tests/fixtures/strategy/**`, `tests/safety/test_stage3_boundaries.py`,
`tests/unit/test_package_layout.py`.

Task 2 owns `DIAGNOSTIC_IDENTITY_V1` and the `_uuid4_shaped` helper in
`crypto_lab/domain/hashing.py`, because Task 2 is the first task that emits a
`Diagnostic` and section 5.3.3 makes that helper a precondition. Task 5 later
adds `STRATEGY_VERSION_V1` to the same enum.

**Consumes:** `CanonicalModel`, `Diagnostic`, `canonical_json_bytes`,
`sha256_bytes`, identifier and financial primitives.
**Produces:** `Result`, `YamlDocument`, `load_yaml_document`, `StrategySpec`
and every sub-model.

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

**Test-first sequence**

1. `Result` discriminates success from failure and cannot carry both.
   **Expected RED:** `ModuleNotFoundError: crypto_lab.domain.results`.
2. `load_yaml_document` rejects a `pathlib.Path` and a `str` path.
   **Expected RED:** `ModuleNotFoundError: crypto_lab.strategy.yaml_source`.
3. One test per forbidden tag, using `invalid/python_tag.yaml` and
   `invalid/unknown_tag.yaml`.
4. Duplicate keys, merge keys, two documents, empty document, BOM, non-UTF-8.
5. One test per bound in section 5.3, including `invalid/billion_laughs.yaml`
   and `invalid/recursive_alias.yaml`.
6. Global-state test: `yaml.SafeLoader.yaml_constructors` unchanged after
   success and after every failure path.
7. Fresh-state test: invalid then valid yields the same result as valid alone.
8. `StrategySpec` accepts `sma_cross_long.valid.yaml` and rejects an unknown
   field.

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

### Task 3 — Closed expression AST and static validation

**Files:** `src/crypto_lab/strategy/expressions.py`,
`src/crypto_lab/strategy/validation.py`,
`tests/unit/strategy/test_strategy_expressions.py`,
`tests/unit/strategy/test_strategy_validation.py`.

**Produces:** the closed discriminated `Expression` union and the static
checker.

**Closed AST** — exactly the nodes in specification section 12.3.1, each a
`CanonicalModel` with a `Literal` `op` discriminator:

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
asset-to-string, scalar-to-series, or timezone conversion. Expression nesting is
bounded by `MAX_EXPRESSION_DEPTH = 24`.

**Test-first sequence**

1. An unknown `op` is rejected. **Expected RED:** module missing.
2. One acceptance and one arity-rejection test per node kind.
3. Type-mismatch tests: boolean operand to `add`; decimal operand to `and`;
   string compared to integer.
4. `bars_ago = -1` rejected with `STRATEGY.REFERENCE_NEGATIVE_OFFSET`.
5. A reference to an undeclared parameter, bar field, or feature is rejected
   with `STRATEGY.REFERENCE_UNKNOWN`.
6. `invalid/future_reference.yaml` is rejected with
   `STRATEGY.REFERENCE_FUTURE_BAR`.
7. Depth beyond `MAX_EXPRESSION_DEPTH` is rejected.
8. Diagnostics from a rule with several errors are complete, deduplicated, and
   sorted by `(rule_id, node_path, error_code)`.

**Focused verification:** `pytest-focused -o addopts= tests\unit\strategy -q`.
**Broader:** `pytest-all`. **Also:** Ruff, strict mypy.

**Security review:** confirm the union is closed, no operator name is resolved
from a string at runtime, and no callable is stored in a model field.

**Independent review gate:** required.

**Commit:** `feat: add closed strategy expression ast`

### Task 4 — Feature DAG and deterministic Level 1 evaluator

**Files:** `src/crypto_lab/strategy/feature_graph.py`,
`src/crypto_lab/strategy/evaluation.py`,
`tests/unit/strategy/test_strategy_feature_graph.py`,
`tests/unit/strategy/test_strategy_evaluation.py`,
`tests/property/test_expression_evaluation.py`,
`tests/fixtures/strategy/golden/**`.

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
5. Golden feature series for `warm_up_boundary`, `crossover_equality`,
   `missing_input`, `bar_offsets`, and `decimal_rounding`.
6. Golden signal series for `sma_cross_long` and `adjacent_entry_exit`.
7. Division by zero yields `STRATEGY.EVALUATION_DIVIDE_BY_ZERO`, not an
   exception or infinity.
8. A non-finite intermediate yields `STRATEGY.EVALUATION_NON_FINITE`.
9. A series longer than `MAX_EVALUATION_BARS` is rejected.
10. Property test: evaluation is a pure function of `(spec, bars)`; two calls
    with equal inputs return equal outputs; the global Decimal context is
    unchanged after evaluation.

**Focused verification:** `pytest-focused -o addopts= tests\unit\strategy tests\property -q`.
**Broader:** `pytest-all`. **Also:** Ruff, strict mypy.

**Security review:** confirm the evaluator has no wall-clock, filesystem,
network, engine, or random access, and that it produces no order, fill, or
portfolio value.

**Independent review gate:** required.

**Commit:** `feat: add feature graph and level 1 evaluator`

### Task 5 — Strategy versioning, extension declarations, and hashing

**Files:** `src/crypto_lab/domain/hashing.py`,
`src/crypto_lab/strategy/versioning.py`, `src/crypto_lab/strategy/loader.py`,
`tests/unit/strategy/test_strategy_versioning.py`,
`tests/unit/strategy/test_strategy_loader.py`,
`tests/property/test_strategy_hashing.py`.

**Produces:** `EngineExtensionDeclaration`, `StrategySourceProvenance`,
`StrategyVersion`, `strategy_version_hash`, `StrategyLoader`.

`StrategyLoader.load(source: bytes, source_name: SourceName, observed_at_utc:
datetime) -> Result[StrategyVersion]`. This matches specification section 8.2's
operation contract; `SourceName` is the constrained non-path label of section
5.2, which narrows section 8.2's `str` without changing parameters, ownership,
sync behaviour, or result semantics.

`EngineExtensionDeclaration` carries `adapter_name`, `extension_id`,
`version`, `content_hash`, `purpose`, `lifecycle_effect`, and
`economic_effect`. The core stores declarations and hashes and never imports or
executes extension code. An extension whose declared economic effect prevents
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

**Files:** `src/crypto_lab/domain/capability_names.py`,
`src/crypto_lab/domain/descriptors.py`,
`src/crypto_lab/domain/comparison_levels.py`,
`src/crypto_lab/domain/identifiers.py`,
`src/crypto_lab/adapters/descriptors.py`,
`src/crypto_lab/capabilities/vocabulary.py`,
`src/crypto_lab/capabilities/models.py`,
`src/crypto_lab/capabilities/policy.py`,
`src/crypto_lab/capabilities/resolver.py`,
`tests/unit/capabilities/**`,
`tests/property/test_compatibility_resolution.py`,
`tests/architecture/test_package_import_boundaries.py`.

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
`tests/unit/capabilities/test_capability_comparison.py`.

**Consumes:** `ComparisonLevel` from `crypto_lab.domain.comparison_levels` and
`ApproximationDeclaration` from `crypto_lab.capabilities.models`. Both are
produced by Task 6, not by this task.

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

### Task 8 — Generated schemas, documentation, acceptance, and status

**Files:** `src/crypto_lab/schema_registry.py`, `schemas/strategy/**`,
`schemas/capabilities/**`, `tests/safety/test_stage3_boundaries.py`,
`tests/unit/test_schema_registry.py`, `docs/development/verification.md`,
`README.md`, `docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md`.

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
6. Update `_ALLOWED_SOURCE_FILES`, `_ALLOWED_IMPORT_ROOTS`, and
   `_DEFERRED_DEFINITIONS` per section 9.8.
7. Update `docs/development/verification.md` with Stage 4 focused checks and
   the 20-file registry, and `README.md` with the status line.
8. Update the Stage 4 row of roadmap section 9 to record implementation
   completion at the final Stage 4 commit.

**Focused verification:** `pytest-focused -o addopts= tests\safety tests\unit -q`.
**Broader:** the complete verifier `scripts/verify.ps1`, which must pass on the
first attempt with no pass-on-rerun.

**Security review:** whole-stage review against section 5 and against the
Stage 4 exclusion list.

**Independent review gate:** whole-stage architecture, security, and diff
review.

**Commit:** `docs: complete project 1 stage 4`

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
2. After Task 8, run a fresh whole-stage independent review covering
   architecture compliance, interface consistency, stage scope, schema
   ownership, YAML security, supply-chain safety, determinism, property-test
   quality, flake resistance, and privacy and network boundaries.
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

### Appendix C — `tests/safety/test_stage3_boundaries.py` patches (Tasks 2, 6, 8)

Add to `_ALLOWED_SOURCE_FILES`, preserving alphabetical order:

```text
"capabilities/comparison.py",
"capabilities/models.py",
"capabilities/policy.py",
"capabilities/resolver.py",
"capabilities/vocabulary.py",
"domain/capability_names.py",
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
5.2's bytes-only contract removes any need for `io`, but items 3 and 12 of that
section do require two roots the merged set lacks, so **three** are added:

```text
"codecs",
"contextlib",
"yaml",
```

`codecs` is needed for the BOM literals in section 5.2 item 3, and
`contextlib` for the explicit `contextlib.closing` of section 5.2 item 12.
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

`test_stage3_completion_status_is_exact` is **not** modified by Stage 4.

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
+    "CapabilityName",
+    "EngineDescriptor",
+    "OperatingSystem",
+    "SupportedSchemaVersion",
+    "VocabularyVersion",
+]
```

The private module helpers `_unique_sorted_text`, `_unique_sorted_versions`,
and `_set_unique_items` move **with** the classes into
`crypto_lab/domain/descriptors.py`. This is mandatory, not tidiness: if they
stayed behind, `domain/descriptors.py` would have to import from
`crypto_lab.adapters.descriptors`, and `crypto_lab.adapters` is in
`_PROHIBITED_PROJECT_PACKAGES` for
`test_repository_domain_package_has_no_prohibited_imports`. That would
re-introduce the exact dependency-direction violation section 5.7 exists to
remove, through the back door.

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
sizes, a `dict[str, list[yaml.Event]]` of recorded anchor event subsequences for
replay,
and a stack of open anchor frames. Its `charge` method is the single place
every ceiling is enforced:

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

1. Every non-alias event charges `1`. Every alias event charges the target
   anchor's recorded **expanded** size, so nested anchors compound and the
   nine-level bomb is rejected. Charging a raw subtree event count instead
   would let that bomb pass every ceiling.
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
appends the modules it creates, starting with Task 2.

The probe asserts that importing project modules performs no file read, so
Task 2 must additionally prove that importing `crypto_lab.strategy.yaml_source`
— and therefore `yaml` — survives it. PyYAML's package import is pure Python
and reads no data file, but this must be demonstrated rather than assumed: if
the probe fails, the correct fix is a deferred function-local `import yaml`
inside `load_yaml_document`, **not** a weakened probe. Record the measured
outcome in the ledger either way.

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
  dependency direction and the section 5.8 Stage 4 / Stage 5 comparison
  boundary.
- No placeholder, no "as needed" instruction, and no unresolved choice remains.
