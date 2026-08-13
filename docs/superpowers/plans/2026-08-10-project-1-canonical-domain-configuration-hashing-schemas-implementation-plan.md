# Project 1 Canonical Domain, Configuration, Hashing, and Schemas Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Project 1 Stage 3's strict, deterministic foundational
domain contracts, explicit local configuration, canonical hashing profiles,
dataset metadata, structural descriptors, artifact-owner union, and generated
JSON Schemas without adding ingestion, orchestration, persistence, processes,
engines, artifact finalization, or network behavior.

**Architecture:** Pydantic v2 models form immutable, extra-forbid canonical
boundaries over small standard-library primitives for UUID4 identifiers,
UTC instants, Decimal strings, semantic versions, canonical JSON, and SHA-256.
Every Stage 3 child that may load Pydantic is started through one closed,
repository-controlled PowerShell launcher that unconditionally injects the
fixed `PYDANTIC_DISABLE_PLUGINS=__all__` dependency control before Python
starts and accepts only the exact offline uv operations needed by the stage.
Configuration loading is an explicit pure precedence operation over named TOML
files and supplied non-secret overrides; dataset, descriptor, and ownership
records remain in-memory metadata only. A deterministic registry generates
Draft 2020-12 schemas into the reviewed root `schemas/` tree, packages those
same bytes once under `crypto_lab/schemas` in wheels, and verifies both source
and built copies without relying on GitNexus or network access.

**Tech Stack:** User-local uv-managed CPython 3.12; Pydantic v2
`>=2.12,<3`; Python standard library (`datetime`, `decimal`, `enum`,
`hashlib`, `json`, `pathlib`, `tomllib`, `uuid`); pytest; Hypothesis
`>=6.130,<7`; jsonschema `>=4.23,<5` with `Draft202012Validator`; Ruff;
mypy strict mode; Hatchling; PowerShell; Git.

## Global Constraints

- Authority order is the approved architecture specification, ADR 0001, the
  master roadmap, repository `AGENTS.md`, reviewed Stage 1 and Stage 2 source,
  this approved plan, then advisory developer-tool output.
- Planning was performed in an isolated worktree from clean local `main` at
  `baa0c8070d0783f72c4625294d8fc5706c16082d`. Execution begins from the later
  clean local-main commit that contains this approved plan. Record that commit
  as `$stage3BaseCommit`, verify it is the merge base with `main`, and make no
  Stage 3 implementation edit in the main checkout.
- `tools/gitnexus/outcome.json` records `DISABLED_WITH_EVIDENCE`. Do not
  install, configure, index, or invoke GitNexus. Satisfy roadmap gate 12 with
  the documented manual source, reference, and base-to-HEAD diff workflow.
- Use only the user-local uv-managed CPython 3.12 selected by `uv`. Before
  implementation, run
  `uv python find --managed-python --system --no-python-downloads 3.12` and
  stop if it does not resolve an existing managed interpreter.
- Ordinary development and every verification command are offline. After the
  Task 1 launcher exists, invoke only its closed named profiles as a separate
  child PowerShell process; never dot-source it. Every ordinary profile pins
  the repository/project, disables ambient uv config and Python downloads,
  requires managed Python 3.12, and includes `--offline`; run profiles also
  include `--no-sync` and `--no-env-file`.
- Task 1 first attempts dependency resolution with launcher profile
  `lock-resolve-offline`. If and
  only if missing cached registry metadata prevents resolution, stop at the
  human gate and present exact launcher profile `lock-acquire`; run it only
  after explicit user approval. After lock resolution, first run launcher
  profile `sync`. If and only if locked distributions are absent locally,
  stop at a second human gate and present exact launcher profile
  `sync-acquire`; run it only after explicit user approval. The two acquisition
  profiles are the only non-offline launcher vectors, are not verification
  evidence, and authorize no later online command.
- Do not hand-edit `uv.lock`. Review its exact package graph and require a
  registry source plus SHA-256 artifact hashes for every registry package.
- Runtime dependencies are exactly `pydantic>=2.12,<3`. Hypothesis and
  jsonschema are development-only dependencies. No engine, exchange,
  networking, persistence, process, YAML, Parquet, dataframe, LLM, cloud, or
  deployment dependency enters Stage 3.
- Every production behavior follows TDD: write the focused failing test, run
  it and record the expected contract failure, write the minimum production
  change, run the focused test green, then run the named broader checks.
- Every task receives a fresh implementer and an independent specification
  reviewer. Production behavior additionally receives a code-quality and
  security review. Resolve every Critical or Important finding before the task
  commit. Narrow correction commits are allowed; never amend a reviewed commit
  and never create an empty verification commit.
- Canonical models are frozen, strict, and reject unknown fields. Stage 3
  persisted top-level records use `schema_version = "1.0.0"`; the embedded
  `ArtifactOwnerRef` union has no invented wrapper version. JSON Schemas use Draft
  2020-12, kebab-case filenames ending `-v1.schema.json`, and stable URN IDs
  `urn:crypto-lab:schema:<area>:<kebab-name>:1.0.0`.
- Treat specification section 33 cumulatively. Stage 3 implements only the
  roadmap-owned foundational subset; later canonical records remain owned by
  their named stages. Do not add a partial later-stage record merely to make
  the complete Project 1 acceptance list appear present early.
- `AdapterDescriptor` and `EngineDescriptor` are structural Stage 3 metadata.
  Normalize and make their capability collections disjoint, but defer
  capability-vocabulary membership and complete-set semantics to Stage 4.
  Stage 3 supplies `SemanticVersion` in `domain/versioning.py` and a pure
  adapter-layer highest-common-stable-version helper for the section 14.2
  foundation. `BootstrapDescriptorEnvelope`,
  `NegotiationResult`, `RuntimeAvailabilityObservation`, protocol envelopes,
  subprocesses, catalogs, and runtime probes remain Stage 6 work.
- Artifact ownership includes all six exact `RUN`, `EXPERIMENT`, `DATASET`,
  `STRATEGY`, `ADAPTER`, and `SYSTEM` variants. Presentation serialization
  emits `owner_kind` first for reviewability. Canonical hash serialization
  still sorts every object key globally; presentation order never changes hash
  bytes.
- Configuration has no ambient-environment layer, user-profile scan, registry
  scan, remote source, credential fallback, or implicit current-directory
  lookup. Files are read only when the caller supplies their exact paths.
  Stage 3 validates path syntax and relative-base resolution but defers actual
  Windows volume, NTFS, network-share, reparse-point, and long-path probes to
  the later filesystem/process stages.
- Stage 3 configuration produces a normalized full audit hash and a base
  material-configuration hash. Stage 5 composes the final experiment hash with
  strategy, dataset, adapter/engine, fee, slippage, execution, and comparison
  inputs; Stage 3 must not invent those orchestration records now.
- Dataset models are metadata contracts only. Do not read, create, hash, move,
  download, normalize, or ingest dataset files. Dataset content hashing in
  Stage 3 consumes validated descriptor and partition metadata in memory.
- Schema generation accepts an explicit output root and constructs every
  target as a lexical descendant of that root. Execution uses only the
  reviewed repository `schemas/` root. Stage 3 does not claim physical
  containment through a pre-existing symlink or Windows reparse-point
  ancestor; Stage 7 retains ownership of volume and reparse-point enforcement.
  Importing any package or generator module performs no file reads,
  environment inspection, network access, process launch, database
  initialization, or path creation.
- Pydantic dependency code alone may read the fixed, non-secret
  `PYDANTIC_DISABLE_PLUGINS=__all__` control while constructing validators or
  schemas. `scripts/invoke-uv.ps1` overwrites any inherited value immediately
  before launching uv, never reads or preserves the prior value, and removes
  the variable only from its child PowerShell environment in `finally`.
  Application, domain, configuration, schema, and CLI modules may not read,
  set, mutate, branch on, print, log, persist, expose, or hash it. The
  fresh-import child permits only the exact dependency call from
  `pydantic.plugin._loader` and fails every application environment access;
  the source scan categorically prohibits `os.getenv` and `os.environ` in
  `src/crypto_lab`. No other environment-variable exception is authorized.
- Preserve the exact Project 1 exclusions: no real trading, credentials,
  API-key handling, withdrawals, live orders, shorting, margin, futures,
  leverage, Binance/exchange integration, market-data download, real backtest,
  paper wallet, tax/TDS, risk engine, dashboard, LLM, Docker, cloud, or server.
- Do not begin Stage 4 during this plan.

---

## Planning baseline and fixed decisions

The plan was authored after fresh offline verification of the Stage 2 main
state: 125 tests passed, branch coverage was 100 percent, strict typing and
Ruff were clean, and both wheel and sdist built. The Stage 2 governance outcome
is `DISABLED_WITH_EVIDENCE`; the only permitted cross-module discovery route
is manual source/reference search plus full diff review.

### Cumulative ownership boundary

| Contract family | Stage 3 owns now | Explicitly deferred owner |
|---|---|---|
| Canonical foundation | strict base model, typed operational IDs, SHA-256, normalized identifiers/codes, UTC, Decimal, `InstrumentRef`, `Money`, `Price`, `Quantity` | strategy/result/lifecycle records in Stages 4, 5, 6, and 9 |
| Diagnostics | immutable bounded `Diagnostic`, severity/category enums, JSON-safe bounded details, direct causal-ID validation | causal-graph repository traversal, redaction/evidence/logging/audit services in Stages 5 and 9 |
| Configuration | exact Stage 3 TOML model, explicit precedence, safe defaults, safety-policy rejection, normalized snapshot and two base hashes | experiment freeze/composition in Stage 5 and Windows storage probes in Stage 7/9 |
| Dataset | descriptor, partition, interval-quality metadata and deterministic metadata hash | repositories in Stage 8 and ingestion/normalization in Project 2 |
| Descriptor | `EngineDescriptor`, structural `AdapterDescriptor`, semantic-version primitive, pure stable intersection helper | vocabulary resolution in Stage 4 and protocol negotiation/catalog/availability in Stage 6 |
| Artifact | all six `ArtifactOwnerRef` variants and deterministic owner presentation/hash | candidate/reference/finalization/provenance records in Stage 9 |
| Schemas | deterministic registry/generator for every Stage 3 top-level model and exact distribution inclusion | schemas for later records in their owning stages |

Section 33.2's phrase "all required records" is a final cumulative Project 1
gate. Stage 3 proves only the foundational rows above and records every absent
later record as deliberately deferred, not missing implementation.

### Canonical schema registry

The generator owns exactly these 11 source files and no wildcard-discovered
models:

| Source path | `$id` | Python model |
|---|---|---|
| `schemas/domain/instrument-ref-v1.schema.json` | `urn:crypto-lab:schema:domain:instrument-ref:1.0.0` | `InstrumentRef` |
| `schemas/domain/money-v1.schema.json` | `urn:crypto-lab:schema:domain:money:1.0.0` | `Money` |
| `schemas/domain/price-v1.schema.json` | `urn:crypto-lab:schema:domain:price:1.0.0` | `Price` |
| `schemas/domain/quantity-v1.schema.json` | `urn:crypto-lab:schema:domain:quantity:1.0.0` | `Quantity` |
| `schemas/domain/diagnostic-v1.schema.json` | `urn:crypto-lab:schema:domain:diagnostic:1.0.0` | `Diagnostic` |
| `schemas/configuration/application-config-v1.schema.json` | `urn:crypto-lab:schema:configuration:application-config:1.0.0` | `ApplicationConfig` |
| `schemas/datasets/dataset-partition-v1.schema.json` | `urn:crypto-lab:schema:datasets:dataset-partition:1.0.0` | `DatasetPartition` |
| `schemas/datasets/dataset-descriptor-v1.schema.json` | `urn:crypto-lab:schema:datasets:dataset-descriptor:1.0.0` | `DatasetDescriptor` |
| `schemas/protocol/engine-descriptor-v1.schema.json` | `urn:crypto-lab:schema:protocol:engine-descriptor:1.0.0` | `EngineDescriptor` |
| `schemas/protocol/adapter-descriptor-v1.schema.json` | `urn:crypto-lab:schema:protocol:adapter-descriptor:1.0.0` | `AdapterDescriptor` |
| `schemas/artifacts/artifact-owner-ref-v1.schema.json` | `urn:crypto-lab:schema:artifacts:artifact-owner-ref:1.0.0` | the six-branch `ArtifactOwnerRef` union generated through `TypeAdapter` |

The root `schemas/` tree is the one reviewed source copy. Hatch includes it in
the sdist at `schemas/...` and force-includes the same files in the wheel at
`crypto_lab/schemas/...`; it must not produce a second root-level wheel copy.

## Exact Stage 3 file map

```text
Modify  pyproject.toml
Modify  uv.lock                                      # generated only by uv
Create  scripts/invoke-uv.ps1
Modify  scripts/verify.ps1
Modify  docs/development/verification.md
Modify  README.md
Modify  docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md
Modify  src/crypto_lab/domain/__init__.py
Create  src/crypto_lab/domain/base.py
Create  src/crypto_lab/domain/identifiers.py
Create  src/crypto_lab/domain/time.py
Create  src/crypto_lab/domain/financial.py
Create  src/crypto_lab/domain/records.py
Create  src/crypto_lab/domain/versioning.py
Create  src/crypto_lab/domain/canonical_json.py
Create  src/crypto_lab/domain/hashing.py
Create  src/crypto_lab/domain/diagnostics.py
Modify  src/crypto_lab/configuration/__init__.py
Create  src/crypto_lab/configuration/models.py
Create  src/crypto_lab/configuration/loader.py
Create  src/crypto_lab/configuration/snapshot.py
Modify  src/crypto_lab/datasets/__init__.py
Create  src/crypto_lab/datasets/models.py
Create  src/crypto_lab/datasets/hashing.py
Modify  src/crypto_lab/adapters/__init__.py
Create  src/crypto_lab/adapters/versioning.py
Create  src/crypto_lab/adapters/descriptors.py
Modify  src/crypto_lab/artifacts/__init__.py
Create  src/crypto_lab/artifacts/ownership.py
Create  src/crypto_lab/schema_registry.py
Create  scripts/generate_schemas.py
Create  scripts/verify_schema_distribution.py
Modify  tests/unit/test_package_layout.py
Modify  tests/safety/test_project_dependencies.py
Modify  tests/safety/test_gitnexus_development_tooling.py
Create  tests/safety/test_uv_launcher.py
Create  tests/safety/test_stage3_boundaries.py
Create  tests/unit/domain/test_identifiers.py
Create  tests/unit/domain/test_time.py
Create  tests/unit/domain/test_financial.py
Create  tests/unit/domain/test_records.py
Create  tests/unit/domain/test_canonical_json.py
Create  tests/unit/domain/test_hashing.py
Create  tests/property/test_canonical_primitives.py
Create  tests/unit/domain/test_diagnostics.py
Create  tests/unit/configuration/test_models.py
Create  tests/unit/configuration/test_loader.py
Create  tests/unit/configuration/test_snapshot.py
Create  tests/unit/datasets/test_models.py
Create  tests/unit/datasets/test_hashing.py
Create  tests/property/test_dataset_hashing.py
Create  tests/unit/adapters/test_versioning.py
Create  tests/unit/adapters/test_descriptors.py
Create  tests/unit/artifacts/test_ownership.py
Create  tests/property/test_artifact_ownership.py
Create  tests/unit/test_schema_registry.py
Create  tests/integration/test_schema_distribution.py
Create  schemas/domain/instrument-ref-v1.schema.json       # generated
Create  schemas/domain/money-v1.schema.json                # generated
Create  schemas/domain/price-v1.schema.json                # generated
Create  schemas/domain/quantity-v1.schema.json             # generated
Create  schemas/domain/diagnostic-v1.schema.json            # generated
Create  schemas/configuration/application-config-v1.schema.json # generated
Create  schemas/datasets/dataset-partition-v1.schema.json   # generated
Create  schemas/datasets/dataset-descriptor-v1.schema.json  # generated
Create  schemas/protocol/engine-descriptor-v1.schema.json   # generated
Create  schemas/protocol/adapter-descriptor-v1.schema.json  # generated
Create  schemas/artifacts/artifact-owner-ref-v1.schema.json # generated
```

No other file is authorized. In particular, do not create configuration TOML
examples, runtime directories, data files, Parquet files, database files,
migrations, runtime protocol-envelope/request/response schemas beyond the two
authorized structural descriptor schemas, strategy schemas, adapter executables,
subprocess code, artifact candidates/references/finalizers, `.codex` files,
GitNexus files, engine runtimes, or network clients.

---

## Execution preflight and review protocol

- [ ] **Create the isolated implementation worktree from the approved plan commit**

From the clean main checkout, record the exact approved-plan HEAD, then create
the implementation worktree using `superpowers:using-git-worktrees`:

```powershell
git status --short
git branch --show-current
$stage3BaseCommit = (git rev-parse HEAD).Trim()
git worktree add `
  ..\Crypto_Trading-worktrees\project-1-stage-3-domain-configuration `
  -b project-1-stage-3-domain-configuration `
  $stage3BaseCommit
```

Required before the first edit in that worktree:

```powershell
git status --short
git branch --show-current
git rev-parse HEAD
git merge-base HEAD main
uv python find --managed-python --system --no-python-downloads 3.12
Get-Content -Raw tools\gitnexus\outcome.json
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

Expected: clean status; branch
`project-1-stage-3-domain-configuration`; `HEAD`, merge base, and
`$stage3BaseCommit` identical; an existing uv-managed CPython 3.12 path;
`DISABLED_WITH_EVIDENCE`; and the complete inherited verifier green. If any
condition differs, stop without editing.

- [ ] **Initialize ignored SDD tracking and record the manual discovery route**

Use the repository-local ignored ledger required by
`superpowers:subagent-driven-development`. Record task state, test commands,
review outcomes, and commit hashes under `.superpowers/sdd/`; do not stage it.
The Stage 3 pre-change discovery note must list these commands and the reviewed
files:

```powershell
rg --files src tests scripts schemas docs AGENTS.md README.md pyproject.toml
rg -n "class |def |type |import |from |schema_version|content_hash" src tests
rg -n "Stage 3|Canonical Domain|Configuration|Hashing|Schemas" `
  docs\superpowers\plans\2026-08-10-project-1-master-roadmap.md
git log -20 --oneline --decorate
```

Review the architecture specification sections named by the Stage 3 roadmap,
ADR 0001, `AGENTS.md`, current package source/tests, and the Stage 2 outcome.
Do not invoke GitNexus.

For every task below, the controller dispatches one fresh implementer, one
fresh specification reviewer, and—when production behavior changes—one fresh
code-quality/security reviewer. Reviewers inspect the task commit plus any
narrow correction commits. No implementer self-review substitutes for those
gates.

### Task 1: Add the exact Stage 3 validation dependencies and lock gates

**Files:**
- Create: `scripts/invoke-uv.ps1`
- Create: `tests/safety/test_uv_launcher.py`
- Modify: `tests/safety/test_project_dependencies.py`
- Modify: `tests/safety/test_gitnexus_development_tooling.py`
- Modify: `pyproject.toml`
- Modify: `uv.lock` (generated only)

**Interfaces:**
- Consumes: the Stage 2 `runtime_dependencies()` safety helper and offline uv
  workflow.
- Produces: a closed offline uv launcher that installs the fixed Pydantic
  dependency control before every relevant child; runtime availability of
  Pydantic v2 and development-only Hypothesis/jsonschema; exact dependency
  assertions used by every later task.

- [ ] **Step 1: Create and independently inspect the prerequisite launcher**

Create `scripts/invoke-uv.ps1` and `tests/safety/test_uv_launcher.py` with the
exact Appendix A.6 contents, in that order. The launcher is prerequisite
repository security/bootstrap tooling rather than application production
behavior, so do not fabricate a TDD red cycle or start Python before it exists.
Before its first use, inspect the complete source and parse it with PowerShell's
AST parser. Require zero parse errors, exactly one dynamic invocation with the
literal extent `& $uvExecutable @uvArguments`, and exactly the closed commands
pinned in the Appendix test. Independently review root pinning,
fixed literal assignment, `finally` cleanup, native exit propagation, exact
profiles, and rejection paths. Record that security review in the SDD ledger.

The tests require all 21 exact closed launcher operation vectors, the bounded focused-pytest
grammar, literal-only environment removal/assignment, no ambient-value
save/read/restore, repository-root/project pinning, unique absolute `uv.exe`
resolution, native exit-code 37 propagation, effective Pydantic plugin
disablement, hostile selection-variable removal, and unchanged test-controlled
parent values. They use only fixed non-secret test values. The `mypy-all`
profile supplies no positional file targets: its fixed
`python -I -B -m mypy` child reads only the repository-owned
`[tool.mypy].files` scope, which is `src` and `tests` through Task 6.

Apply these exact changes to
`tests/safety/test_project_dependencies.py`:

```diff
-"""Keep every Stage 1 runtime dependency group empty and engine-free."""
+"""Keep Project 1 dependencies minimal, exact, and engine-free."""
@@
-    "pydantic",
@@
 _REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
+_EXPECTED_RUNTIME_REQUIREMENTS = ("pydantic>=2.12,<3",)
+_EXPECTED_DEVELOPMENT_NAMES = {
+    "hatchling",
+    "hypothesis",
+    "jsonschema",
+    "mypy",
+    "pytest",
+    "pytest-cov",
+    "ruff",
+}
@@
-def test_project_runtime_dependencies_are_empty(repository_root: Path) -> None:
+def test_project_runtime_dependencies_are_exact(repository_root: Path) -> None:
     document = _load_pyproject(repository_root / "pyproject.toml")
-    assert runtime_dependencies(document) == ()
+    assert (
+        tuple(dependency.requirement for dependency in runtime_dependencies(document))
+        == _EXPECTED_RUNTIME_REQUIREMENTS
+    )
@@
-    assert declared == {"hatchling", "mypy", "pytest", "pytest-cov", "ruff"}
+    assert declared == _EXPECTED_DEVELOPMENT_NAMES
+
+
+def test_lock_registry_artifacts_are_sha256_pinned(repository_root: Path) -> None:
+    document = _load_pyproject(repository_root / "uv.lock")
+    packages = document.get("package")
+    assert isinstance(packages, list)
+    for package in packages:
+        package_table = _mapping(package, "package entry")
+        name = package_table.get("name")
+        assert isinstance(name, str)
+        source = _mapping(package_table.get("source"), "package source")
+        if name == "crypto-trading-lab":
+            assert source == {"editable": "."}
+            continue
+        assert set(source) == {"registry"}
+        assert source["registry"] == "https://pypi.org/simple"
+        wheels = package_table.get("wheels", [])
+        assert isinstance(wheels, list)
+        artifacts: list[object] = list(wheels)
+        sdist = package_table.get("sdist")
+        if sdist is not None:
+            artifacts = [sdist, *artifacts]
+        assert artifacts, package_table["name"]
+        for artifact in artifacts:
+            artifact_table = _mapping(artifact, "locked artifact")
+            digest = artifact_table.get("hash")
+            assert isinstance(digest, str)
+            assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None
```

Replace the Python dependency assertion in
`tests/safety/test_gitnexus_development_tooling.py` with:

```python
assert project["dependencies"] == ["pydantic>=2.12,<3"]
assert "optional-dependencies" not in project
assert "gitnexus" not in serialized
```

The surrounding GitNexus lockfile-absence assertion remains unchanged.

- [ ] **Step 2: Prove the dependency-free launcher contract through itself**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-launcher-bootstrap
```

Expected: every selected non-privilege-dependent contract passes. On Windows,
`test_launcher_rejects_reparse_point_test_target` may be the sole skip, and
only with the fixed reason `Windows test principal cannot create a symbolic
link`. The privilege-free
`test_launcher_rejects_junction_target_without_optional_privilege` contract
must pass and prove deterministic reparse-point rejection; any other skip or
failure blocks the task. Record the optional skip explicitly. The two
dependency availability/proof tests are excluded because Stage 3 dependencies
are not yet declared. No unguarded Python process has run: the inherited pytest
is a child of the reviewed launcher and therefore receives the fixed control
before its interpreter starts. This one closed bootstrap profile injects exact
`-o addopts=` arguments before its fixed test path so the inherited Project 1
coverage addopts cannot require the not-yet-declared coverage dependencies;
ordinary and focused post-bootstrap pytest profiles retain the complete
coverage policy.

- [ ] **Step 3: Write and run dependency-policy tests red through the launcher**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= `
  tests\safety\test_uv_launcher.py::test_validation_libraries_are_available `
  tests\safety\test_project_dependencies.py `
  tests\safety\test_gitnexus_development_tooling.py -q
```

Expected: failure because runtime dependencies are still empty and
Hypothesis/jsonschema are absent from the dev group. No test may pass by
weakening the engine/network dependency denylist.

- [ ] **Step 4: Apply the exact project metadata change**

```diff
 [project]
@@
-dependencies = []
+dependencies = [
+  "pydantic>=2.12,<3",
+]
@@
 dev = [
  "hatchling>=1.27,<2",
+  "hypothesis>=6.130,<7",
+  "jsonschema>=4.23,<5",
  "mypy>=1.15,<2",
@@
 extend-exclude = [
   "docs/superpowers/plans/2026-08-10-project-1-foundation-implementation-plan.md",
+  "docs/superpowers/plans/2026-08-10-project-1-canonical-domain-configuration-hashing-schemas-implementation-plan.md",
 ]
```

Do not alter any other dependency, loosen a version range, or broaden the Ruff
exclusion. Ruff 0.16.2 must continue checking every other discovered file; the
single added exclusion protects this reviewed immutable execution plan's
Python fences from formatter rewrites.

- [ ] **Step 5: Resolve and acquire through the exact offline-first gates**

Run first:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 lock-resolve-offline
```

If it exits zero, continue without a network approval. If it fails solely
because registry metadata is missing, stop and obtain explicit approval for
exactly:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 lock-acquire
```

After a successful generated lock, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 lock-check
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 sync
```

If sync fails solely because locked distributions are missing, stop and obtain
explicit approval for exactly:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 sync-acquire
```

Then rerun both ordinary launcher commands. Never use `uv run --frozen`, never
hand-edit the lock, and record whether either one-time human gate occurred.

- [ ] **Step 6: Review the generated lock and run the focused tests green**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= `
  tests\safety\test_uv_launcher.py `
  tests\safety\test_project_dependencies.py `
  tests\safety\test_gitnexus_development_tooling.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pydantic-proof
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 ruff-check-all
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 mypy-all
git diff --check
```

Inspect `uv.lock` in full. The project package must be the sole local source
and use exactly `{ editable = "." }`; every other package must use only the
exact HTTPS PyPI registry source and SHA-256 sdist/wheel hashes. The project
entry must contain Pydantic as runtime and Hypothesis/jsonschema only in dev
metadata. Confirm no
engine, exchange, network client, SQLAlchemy, Alembic, PyArrow, dataframe,
YAML, LLM, GitNexus, Docker, or deployment package entered the lock.

- [ ] **Step 7: Independent review and commit**

The specification reviewer confirms exact ranges and the approval-gated
network procedure. The security reviewer checks the lock graph and both safety
tests. After material findings are resolved:

```powershell
git diff -- pyproject.toml uv.lock scripts\invoke-uv.ps1 `
  tests\safety\test_uv_launcher.py `
  tests\safety\test_project_dependencies.py `
  tests\safety\test_gitnexus_development_tooling.py
git status --short
git add pyproject.toml uv.lock scripts\invoke-uv.ps1 `
  tests\safety\test_uv_launcher.py `
  tests\safety\test_project_dependencies.py `
  tests\safety\test_gitnexus_development_tooling.py
git commit -m "chore: add stage 3 validation dependencies"
```

Expected staged paths: exactly those six files.

---

### Task 2: Implement strict identifiers, UTC, Decimal, and financial records

**Files:**
- Create: `src/crypto_lab/domain/base.py`
- Create: `src/crypto_lab/domain/identifiers.py`
- Create: `src/crypto_lab/domain/time.py`
- Create: `src/crypto_lab/domain/financial.py`
- Create: `src/crypto_lab/domain/records.py`
- Create: `tests/unit/domain/test_identifiers.py`
- Create: `tests/unit/domain/test_time.py`
- Create: `tests/unit/domain/test_financial.py`
- Create: `tests/unit/domain/test_records.py`
- Create: `tests/property/test_canonical_primitives.py`
- Modify: `tests/unit/test_package_layout.py`

**Interfaces:**
- Produces: `CanonicalModel`; the ten normative prefixed ID aliases plus the
  reviewed `strv_` strategy-version and `part_` dataset-partition conventions;
  `Sha256`, `NormalizedIdentifier`, `AssetCode`; `exact_string_schema`;
  `UtcDateTime`;
  `CanonicalDecimal`, `PositiveDecimal`, `NonNegativeDecimal`;
  `InstrumentRef`, `Money`, `Price`, and `Quantity`.
- Consumed later by: every Stage 3 model, canonical serializer, hashes, schemas,
  and later Project 1 stages.

- [ ] **Step 1: Write focused tests for every primitive and record invariant**

Use literal `schema_version="1.0.0"` in every valid example. The four unit
files must contain parameterized assertions for this exact matrix:

| Contract | Valid examples | Required rejection examples |
|---|---|---|
| IDs | lowercase canonical UUID4 with the matching `exp_`, `run_`, `art_`, `ds_`, `strat_`, `inv_`, `evt_`, `cand_`, `diag_`, `audit_` prefix | wrong prefix, UUID1, nil UUID, uppercase UUID, braces, missing prefix, leading/trailing whitespace |
| SHA-256 | exactly 64 lowercase hex characters | uppercase, wrong length, non-hex, whitespace |
| names/codes | normalized lowercase names; uppercase asset/venue codes | spaces, uppercase normalized name, lowercase asset code, empty, punctuation outside `._-` |
| instrument ID | direct `TypeAdapter(InstrumentId)` validation of canonical venue/base/quote components from one through 32 characters | malformed separators or market type; lowercase or malformed components; each of venue, base, and quote at 33 characters |
| UTC | aware `datetime.UTC` datetime and JSON string ending `Z` | naive datetime; nonzero offset; invalid date; Python string passed to strict `model_validate` |
| Decimal | typed `Decimal("0")`, `Decimal("1E+3")`, and `Decimal("1.2300")` normalized to JSON strings `"0"`, `"1000"`, and `"1.23"`; canonical JSON string `"1.23"` | JSON numeric tokens, Python float/int/bool, noncanonical JSON/string forms `"1E+3"`, `"1.2300"`, `"1.0"`, plus signs, leading zeros, negative zero, NaN, Infinity, malformed/empty/whitespace string |
| `InstrumentRef` | `BINANCE:BTC/USDT:SPOT` reconstructed from fields | different canonical ID, same base/quote, malformed ID, unknown market type, unknown field |
| `Money` | finite signed amount with explicit asset code | float amount, noncanonical string, unknown field |
| `Price` | positive value whose quote matches instrument ID | zero/negative value, mismatched quote, malformed instrument ID |
| `Quantity` | non-negative value whose base matches instrument ID | negative value, mismatched base, malformed instrument ID |

The tests must exercise both `model_validate()` with typed Python values and
`model_validate_json()` with canonical JSON strings. Use this exact unknown
field proof for every top-level model:

```python
with pytest.raises(ValidationError, match="extra_forbidden"):
    InstrumentRef.model_validate(
        {
            **VALID_INSTRUMENT,
            "unexpected": "rejected",
        }
    )
```

The `InstrumentRef` same-base/quote regression must use the otherwise
self-consistent canonical ID `BINANCE:BTC/BTC:SPOT`; a mismatched canonical ID
would let reconstruction validation mask removal of the distinct-assets
invariant. Appendix A.9 supplies both that mutation-sensitive case and the
exact `extra_forbidden` assertion above.

Create `tests/property/test_canonical_primitives.py` with exactly the Task 2
contents in Appendix A.9. Its `DecimalProbe` and `UtcProbe` are test-local
`CanonicalModel` classes; production modules must not expose probe APIs. The
file uses genuine Hypothesis strategies with naive `min_value`/`max_value`
bounds plus `timezones=st.just(UTC)`, parses the serialized JSON value before
checking exponent absence, and exercises both primitive round trips. Task 2
must not import `canonical_json` from this property file; Task 3 appends that
property only after the serializer exists.

Apply this exact cumulative patch to the inherited
`tests/unit/test_package_layout.py` in the same red-test change. It is against
the Stage 1 file currently in the repository: `sys` is already imported in
both the parent and child, and the child has not replaced `os.environ`. The
parent pytest process starts through `scripts/invoke-uv.ps1`; its direct
`sys.executable` child inherits the fixed control, installs the reviewed
`os.getenv` guard before any project or Pydantic import, and imports every
module created in Task 2. No application configuration exception is
introduced:

```diff
@@
     "crypto_lab.domain",
+    "crypto_lab.domain.base",
+    "crypto_lab.domain.identifiers",
+    "crypto_lab.domain.time",
+    "crypto_lab.domain.financial",
+    "crypto_lab.domain.records",
     "crypto_lab.strategy",
@@
 def _unexpected_operation(*args: object, **kwargs: object) -> NoReturn:
@@
     raise AssertionError("package import attempted a forbidden side effect")


-os.getenv = _unexpected_operation
+def _guarded_getenv(key: str, default: object = None) -> str:
+    del default
+    caller_module = sys._getframe(1).f_globals.get("__name__")
+    if (
+        key == "PYDANTIC_DISABLE_PLUGINS"
+        and caller_module == "pydantic.plugin._loader"
+    ):
+        return "__all__"
+    return _unexpected_operation(key, caller_module)
+
+
+os.getenv = _guarded_getenv
```

Task 2 deliberately does not add an `os.environ` replacement that was absent
from the inherited file. Task 7 replaces the complete test with the final,
broader exact guard body in Appendix A.8. Until then, the Task 2 child retains
all inherited guards, and the dependency-only `getenv` shim permits only the
exact Pydantic loader call without consulting ambient state.

- [ ] **Step 2: Run the new tests red**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\domain `
  tests\property\test_canonical_primitives.py `
  tests\unit\test_package_layout.py -q
```

Expected: collection errors naming absent `crypto_lab.domain` modules and
types. A red failure caused only by a misspelled import is corrected before
production code is written.

- [ ] **Step 3: Implement the strict common model and typed primitives**

`src/crypto_lab/domain/base.py` defines exactly:

```python
"""Strict immutable base classes for canonical Project 1 records."""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict

SCHEMA_VERSION = "1.0.0"


class CanonicalModel(BaseModel):
    """Reject coercion, mutation, unknown fields, and invalid defaults."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
        validate_default=True,
    )
```

`identifiers.py` defines `PrefixedUuid4` validation without generating IDs or
reading global state. The shared validator must execute this exact algorithm:

```python
def validate_prefixed_uuid4(value: str, prefix: str) -> str:
    if not value.startswith(prefix):
        raise ValueError(f"identifier must start with {prefix!r}")
    suffix = value.removeprefix(prefix)
    parsed = UUID(suffix)
    if parsed.version != 4 or str(parsed) != suffix:
        raise ValueError("identifier must contain a lowercase canonical UUID4")
    return value
```

Expose the ten normative families `ExperimentId`, `RunId`, `ArtifactId`,
`DatasetId`, `StrategyId`, `InvocationId`, `EventId`, `CandidateArtifactId`,
`DiagnosticId`, and `AuditEventId` as distinct `Annotated[str, ...]` aliases.
Use `strat_` only for `StrategyId`. Stage 3 additionally fixes the unambiguous
implementation conventions `strv_<uuid4>` for `StrategyVersionId` and
`part_<uuid4>` for `DatasetPartitionId`; later stages consume rather than
reinterpret those prefixes. Each validator closes over only its named prefix.
Use the exact PEP 695 aliases and strict constraints from Appendix A.1. The
three non-prefixed aliases have this exact shape:

```python
type Sha256 = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$"),
    WithJsonSchema(exact_string_schema(r"^[0-9a-f]{64}$")),
]
type NormalizedIdentifier = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    ),
    WithJsonSchema(
        exact_string_schema(
            r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
            min_length=1,
            max_length=128,
        )
    ),
]
type AssetCode = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=32,
        pattern=r"^[A-Z][A-Z0-9]*(?:[._-][A-Z0-9]+)*$",
    ),
    WithJsonSchema(
        exact_string_schema(
            r"^[A-Z][A-Z0-9]*(?:[._-][A-Z0-9]+)*$",
            min_length=1,
            max_length=32,
        )
    ),
]
```

`exact_string_schema` is the pure Appendix A.1 helper used by these aliases
and later Stage 3 canonical string types.
It replaces only a schema pattern's final `$` with `(?![\s\S])`; runtime
`StringConstraints` retain their Rust-compatible patterns. This gives both
validation and serialization schemas an ECMA-262/Python-compatible absolute
end and prevents terminal line terminators from passing schema validation.

Do not subclass `str` with a permissive constructor and do not generate a UUID
inside validation.

`time.py` supplies `UtcDateTime`. Its validator
requires `tzinfo` and `utcoffset() == timedelta(0)`, normalizes the value to
`datetime.UTC`, and its `PlainSerializer` emits
`value.isoformat(timespec="seconds" if value.microsecond == 0 else
"microseconds").replace("+00:00", "Z")`. This omits the fractional component
when it is zero and otherwise emits exactly six fractional digits. Do not
silently convert a non-UTC offset. Test-only probe models live in the tests.

`financial.py` supplies `CanonicalDecimal`, `PositiveDecimal`, and
`NonNegativeDecimal`. The before-validator
uses `ValidationInfo.mode` to distinguish trusted typed Python input from JSON
input. Python mode accepts only a `Decimal`; JSON mode accepts only an already
canonical string matching the sign-specific Appendix A.1 patterns. It
rejects every JSON numeric token, Python `int`, `float`, and `bool`, non-finite
value, signed zero, redundant fractional zero, exponent string, plus sign, and
leading zero. Format a typed Decimal from `as_tuple()` and fixed-point digit
placement without calling `Decimal.normalize()` or consulting the ambient
decimal context. Positive and non-negative aliases add the named sign
predicate. Validation and serialization JSON Schemas are string-only with the
canonical regex and explicit `maxLength`; neither declares JSON number.

- [ ] **Step 4: Implement the four foundational records**

`records.py` defines:

```python
class MarketType(StrEnum):
    SPOT = "SPOT"
    MARGIN = "MARGIN"
    FUTURES = "FUTURES"
    EQUITIES = "EQUITIES"


class InstrumentRef(CanonicalModel):
    schema_version: Literal["1.0.0"]
    canonical_id: InstrumentId
    venue: AssetCode
    base_asset: AssetCode
    quote_asset: AssetCode
    market_type: MarketType


class Money(CanonicalModel):
    schema_version: Literal["1.0.0"]
    currency: AssetCode
    amount: CanonicalDecimal


class Price(CanonicalModel):
    schema_version: Literal["1.0.0"]
    instrument_id: InstrumentId
    quote_asset: AssetCode
    value: PositiveDecimal


class Quantity(CanonicalModel):
    schema_version: Literal["1.0.0"]
    instrument_id: InstrumentId
    base_asset: AssetCode
    value: NonNegativeDecimal
```

Use `model_validator(mode="after")` methods to enforce:

```text
InstrumentRef: base_asset != quote_asset and canonical_id equals
               f"{venue}:{base_asset}/{quote_asset}:{market_type.value}"
Price:          parse <VENUE>:<BASE>/<QUOTE>:<MARKET_TYPE> and require quote_asset == QUOTE
Quantity:       parse the same form and require base_asset == BASE
```

The parser uses one anchored regular expression and validates all four
components; it never guesses from a partial string. `InstrumentId` composes
its strict string constraints with an `AfterValidator` that calls that public
parser and returns the original string, so direct alias validation enforces
the same one-through-32-character venue/base/quote bounds as record
validation. Its validation and serialization JSON Schemas use the intersection
of the canonical grammar and an anchored component-bounds pattern, with only
the reviewed terminal negative lookahead supplying an absolute end, so Draft
2020-12 consumers enforce the same bounds. Market types
outside the enum fail. Do not modify `domain/__init__.py` in Task 2. Task 4
owns the final import-only public surface after canonical JSON, diagnostics,
and versioning all exist.

- [ ] **Step 5: Run focused and broader green checks**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\domain `
  tests\property\test_canonical_primitives.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= `
  tests\architecture\test_domain_import_boundary.py `
  tests\unit\test_package_layout.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 ruff-format-all
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 ruff-check-all
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 mypy-all
git diff --check
```

Expected: all named tests pass; Hypothesis executes generated examples; domain
AST boundary remains empty; no file/environment/network/process operation
occurs at import.

- [ ] **Step 6: Independent review and commit**

Review all strictness, JSON shape, Decimal/UTC rejection, ID class separation,
and dependency direction. Then:

```powershell
git add src\crypto_lab\domain `
  tests\unit\domain\test_identifiers.py `
  tests\unit\domain\test_time.py `
  tests\unit\domain\test_financial.py `
  tests\unit\domain\test_records.py `
  tests\property\test_canonical_primitives.py `
  tests\unit\test_package_layout.py
git commit -m "feat: add canonical domain primitives"
```

---

### Task 3: Add canonical JSON, named SHA-256 profiles, and diagnostics

**Files:**
- Create: `src/crypto_lab/domain/canonical_json.py`
- Create: `src/crypto_lab/domain/hashing.py`
- Create: `src/crypto_lab/domain/diagnostics.py`
- Create: `tests/unit/domain/test_canonical_json.py`
- Create: `tests/unit/domain/test_hashing.py`
- Create: `tests/unit/domain/test_diagnostics.py`
- Modify: `tests/property/test_canonical_primitives.py`

**Interfaces:**
- Consumes: `CanonicalModel`, Decimal formatting, UTC formatting, and `Sha256`.
- Produces: `canonical_json_bytes(value) -> bytes`,
  `canonical_json_text(value) -> str`, `HashingProfile`,
  `CanonicalHashEnvelope`, `profile_hash(profile, payload) -> Sha256`, and
  `attempt_token_hash(token) -> Sha256`; `DiagnosticSeverity`,
  `DiagnosticCategory`, and the strict bounded `Diagnostic` model.

- [ ] **Step 1: Write the exact golden and rejection tests from Appendix A**

The canonical JSON golden byte string is UTF-8 without BOM, sorted at every
object level, compact, Unicode-preserving, fixed-point Decimal, UTC `Z`, and
array-order-preserving. Tests must reject float, bytes, set, non-string mapping
keys including `str` subclasses and `StrEnum` keys, naive/non-UTC datetimes,
and arbitrary objects before `json.dumps` can coerce them. Apply the exact
Task 3 Appendix A.9 patch that adds the canonical key-order property only now,
after `canonical_json.py` exists. The attempt-token golden vector is:

```text
token: token-123
sha256: c2e83ef7cf00c619f6cfb843bcfffbb91da6ae7b26de5110f36db68762ec74de
```

The system-owner profile envelope golden hash is:

```text
canonical bytes: {"hashing_profile":"artifact-owner/v1","payload":{"core_component":"schema_registry","correlation_id":"stage3","owner_kind":"SYSTEM"},"schema_version":"1.0.0"}
sha256: 1ec94f41e62924c7715e7a6cd4c34cfa05af92060ecd7f05b8ebba580d213b11
```

- [ ] **Step 2: Run focused tests red**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= `
  tests\unit\domain\test_canonical_json.py `
  tests\unit\domain\test_hashing.py `
  tests\unit\domain\test_diagnostics.py -q
```

Expected: absent-module collection failures.

- [ ] **Step 3: Apply the exact Task 3 file contents from Appendix A**

`canonical_json.py` recursively normalizes only Pydantic models, exact built-in
dictionaries with string keys, exact built-in tuples/lists, `StrEnum`,
`Decimal`, UTC `datetime`, strings, integers, booleans, and null. It rejects
every float, subclass-based coercion, and unknown object.
`hashing.py` wraps profile payloads in the explicit immutable envelope
`{"schema_version":"1.0.0","hashing_profile":...,"payload":...}`. The only
raw byte-domain profile is the normative attempt-token formula:

```python
sha256(b"crypto_lab:attempt-token:v1" + b"\x00" + token.encode("utf-8"))
```

No other profile uses an undocumented byte prefix or omits its profile name.
The exact diagnostic implementation in Appendix A validates stable uppercase
namespaced codes, bounded messages/details, absent-or-typed correlations,
unique non-self causal IDs, and JSON-safe detail values. Draft 2020-12 exposes
the error-code pattern and recursive per-string, per-integer, per-list,
per-object, and key bounds. Aggregate depth, node count, encoded-byte size, and
normalized secret-like-key checks remain runtime-only and are tested directly.
The key-name guard covers separated, camelCase, compact, and plural spellings,
including `apiKey`, `accessToken`, `authToken`, `attemptToken`, and
`credentials`; it does not inspect or claim arbitrary values secret-free.
`ENGINE_RUNTIME`, `PROTOCOL`, `TIMEOUT`, and `CANCELLATION` findings require an
`invocation_id`; other categories may represent pre-command facts. A describe
invocation may exist without a run, while a run still requires an experiment.
Cross-record causal-cycle traversal remains a later repository/service
responsibility.

Pydantic 2.12's `MISSING` sentinel represents omission for the four optional
correlations: defaults disappear from Python/JSON dumps and schemas, while an
explicit JSON/Python null is invalid. Mypy does not yet implement PEP 661
sentinel-as-type syntax, so exactly the four field declarations carry
`# type: ignore[valid-type]`; an `object`-typed helper performs identity tests
without broader ignores. Direct construction, dump, round-trip, null-rejection,
schema, Ruff, and strict-mypy tests pin this narrow treatment.

- [ ] **Step 4: Run focused, property, and architecture checks green**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= `
  tests\unit\domain\test_canonical_json.py `
  tests\unit\domain\test_hashing.py `
  tests\unit\domain\test_diagnostics.py `
  tests\property\test_canonical_primitives.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= `
  tests\architecture\test_domain_import_boundary.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 ruff-format-all
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 ruff-check-all
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 mypy-all
git diff --check
```

- [ ] **Step 5: Independent review and commit**

The security reviewer checks that no implicit serialization, NaN/Infinity,
locale, path, environment, randomized hash, or unordered collection can enter
hash bytes. Then:

```powershell
git add src\crypto_lab\domain\canonical_json.py `
  src\crypto_lab\domain\hashing.py `
  src\crypto_lab\domain\diagnostics.py `
  tests\unit\domain\test_canonical_json.py `
  tests\unit\domain\test_hashing.py `
  tests\unit\domain\test_diagnostics.py `
  tests\property\test_canonical_primitives.py
git commit -m "feat: add canonical hashing and diagnostics"
```

---

### Task 4: Add structural descriptors, stable version selection, and artifact owners

**Files:**
- Create: `src/crypto_lab/domain/versioning.py`
- Modify: `src/crypto_lab/domain/__init__.py`
- Create: `src/crypto_lab/adapters/versioning.py`
- Create: `src/crypto_lab/adapters/descriptors.py`
- Modify: `src/crypto_lab/adapters/__init__.py`
- Create: `src/crypto_lab/artifacts/ownership.py`
- Modify: `src/crypto_lab/artifacts/__init__.py`
- Create: `tests/unit/adapters/test_versioning.py`
- Create: `tests/unit/adapters/test_descriptors.py`
- Create: `tests/unit/artifacts/test_ownership.py`
- Create: `tests/property/test_artifact_ownership.py`

**Interfaces:**
- Produces: domain-owned `SemanticVersion`; pure
  `highest_common_stable_version(core, adapter)`; `EngineDescriptor`;
  structural `AdapterDescriptor`; six immutable owner models;
  `ArtifactOwnerRef`; `ARTIFACT_OWNER_ADAPTER`; `owner_presentation()`; and
  `artifact_owner_hash()`.
- Defers: capability-vocabulary membership/resolution to Stage 4 and all
  bootstrap/protocol negotiation, availability observation, catalog,
  executable inspection, and subprocess behavior to Stage 6.

- [ ] **Step 1: Write the exact version, descriptor, and owner tests from Appendix A**

Version tests accept only canonical stable `MAJOR.MINOR.PATCH` strings with no
leading zeros and reject `latest`, `v1.2.3`, missing components, prerelease,
build metadata, whitespace, and non-string coercion. The pure helper treats
input collections as sets, rejects duplicates inside either collection,
validates every value in both inputs before calculating any intersection,
intersects exact values, and returns the numerically highest common stable
version or `None`; it mutates neither input. Invalid values fail even when they
occur only on a non-common side, and the tests pin that behavior.

Descriptor tests prove strict unknown-field rejection, explicit normalized
names and versions, sorted unique version/OS/requirement/limitation tuples,
and disjoint native/approximated/unsupported capability collections. They
deliberately accept an unknown but syntactically normalized capability string
because Stage 4 owns vocabulary membership, and they allow descriptive
`network_required`/`credentials_required` true while proving that descriptor
construction launches nothing and does not change the fixed application
policy.

Owner tests cover all six exact variants:

```text
RUN         experiment_id, run_id, optional invocation_id
EXPERIMENT  experiment_id
DATASET     dataset_id
STRATEGY    exactly one of strategy_version_id or strategy_version_hash
ADAPTER     adapter_name, adapter_version, optional all-or-none engine_name/version
SYSTEM      core_component, correlation_id
```

Every other identifier is rejected as an unknown field by the selected branch.
The real Hypothesis suite generates discriminator/field cross-products and
proves exactly-one-branch validation, required/prohibited combinations,
adapter engine-pair agreement, strategy exclusive-or, deterministic owner
hashes, and mutation rejection. Registry relationship facts such as a run's
membership in an experiment are deferred to Stage 8 persistence and are not
fabricated in the value model.

- [ ] **Step 2: Run the focused tests red**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= `
  tests\unit\adapters `
  tests\unit\artifacts `
  tests\property\test_artifact_ownership.py -q
```

Expected: absent module/type collection failures.

- [ ] **Step 3: Apply the exact Task 4 contents from Appendix A**

`SemanticVersion` belongs to `domain/versioning.py`; the adapter module imports
it. Task 4 also applies the final import-only `domain/__init__.py` surface from
Appendix A.1; Tasks 2 and 3 deliberately leave that file unchanged. No
semantic-version wrapper record or standalone schema is introduced.
`AdapterDescriptor` normalizes capability tuple ordering and checks only syntax,
uniqueness, and cross-set disjointness. It does not claim a complete vocabulary.

`ArtifactOwnerRef` is an `Annotated` six-branch Pydantic union discriminated by
`owner_kind`, not a wrapper record. `owner_presentation()` calls
`model_dump(mode="json")`; Pydantic's `MISSING` sentinel omits absent optional
fields from both Python and JSON serialization. It then constructs a new mapping
with `owner_kind` inserted first. `artifact_owner_hash()` places that mapping
inside the closed `ARTIFACT_OWNER_V1` profile envelope; canonical JSON then
sorts all keys globally. `StrategyArtifactOwner` and `AdapterArtifactOwner`
attach reviewed `json_schema_extra` conditionals so their rendered Draft
2020-12 schemas express the strategy exclusive-or and adapter engine-pair
contract, respectively. Tests must prove both ordering contracts and validate
positive and negative owner instances against the final rendered schema.

- [ ] **Step 4: Run focused, property, import, and architecture checks green**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\adapters `
  tests\unit\artifacts tests\property\test_artifact_ownership.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= `
  tests\architecture\test_domain_import_boundary.py `
  tests\unit\test_package_layout.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 ruff-format-all
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 ruff-check-all
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 mypy-all
git diff --check
```

- [ ] **Step 5: Independent review and commit**

Reviewers confirm there is no Stage 4 resolver/vocabulary policy and no Stage 6
protocol/runtime leakage. Then:

```powershell
git add src\crypto_lab\domain\versioning.py `
  src\crypto_lab\domain\__init__.py `
  src\crypto_lab\adapters src\crypto_lab\artifacts `
  tests\unit\adapters tests\unit\artifacts `
  tests\property\test_artifact_ownership.py
git commit -m "feat: add descriptors and artifact owners"
```

---

### Task 5: Implement explicit strict TOML configuration and base snapshots

**Files:**
- Create: `src/crypto_lab/configuration/models.py`
- Create: `src/crypto_lab/configuration/loader.py`
- Create: `src/crypto_lab/configuration/snapshot.py`
- Modify: `src/crypto_lab/configuration/__init__.py`
- Create: `tests/unit/configuration/test_models.py`
- Create: `tests/unit/configuration/test_loader.py`
- Create: `tests/unit/configuration/test_snapshot.py`

**Interfaces:**
- Consumes: canonical models, JSON, SHA-256 profiles, Decimal/time-safe JSON
  values, `Sha256`, `NormalizedIdentifier`, and `SemanticVersion`.
- Produces: `ApplicationConfig`, closed `RetryTerminalState`, strict partial `ConfigurationLayer`,
  allowlisted `CliOverrides`, `load_configuration(...)`, `ConfigSnapshot`,
  `snapshot_configuration(config)`, `configuration_audit_hash(config)`, and
  `material_base_configuration_hash(config)`.

- [ ] **Step 1: Write the exact model, precedence, I/O, and hashing tests from Appendix A**

The test matrix is exact:

1. Compiled defaults equal every default and bound in specification 22.2.1.
2. Every nested model and partial layer rejects unknown fields.
3. Primary TOML, optional local override TOML, and CLI overrides merge in the
   exact order defaults < primary < local < CLI.
4. Every supplied TOML layer requires `schema_version = "1.0.0"`; the local
   layer cannot differ from the primary.
5. A local override without an explicitly supplied primary is rejected.
6. The caller supplies absolute `primary_path`, `local_override_path`, and
   `invocation_base`; relative source paths are rejected rather than resolved
   through the ambient current directory.
7. Configured relative roots resolve lexically against the primary file's
   parent, or the explicit invocation base when no primary file is supplied.
8. No call reads a directory, profile, registry, environment variable, remote
   source, `.env`, or credential store. Monkeypatch `os.getenv`, `os.environ`,
   `Path.home`, `Path.expanduser`, `socket.create_connection`, and
   `urllib.request.urlopen` to fail while explicit-file loading succeeds. Each
   explicit TOML source is read through a bounded binary stream for at most
   `MAX_CONFIGURATION_BYTES + 1` bytes and is rejected before decode or parse
   when that sentinel byte is present.
9. `CliOverrides` contains only the specification's `Yes` fields and cannot
   represent database, protocol-ceiling, logging-limit, adapter-entry, or
   policy changes.
10. Policy values are literal false; credentials, live, network, shell
    strings, shorting, margin, futures, leverage other than the fixed Project 1
    boundary, and secret-like runtime-metadata keys are rejected.
11. Heartbeat, timeout, concurrency, retry, protocol, logging, filename, and
    path bounds fail exactly outside the table's limits; missing heartbeat is
    at least twice heartbeat interval.
12. Retry states are a unique subset normalized in fixed order `FAILED`,
    `TIMED_OUT`, `UNAVAILABLE` and fresh availability is literal true.
13. The audit hash changes for every field that has more than one valid value.
    The material-base hash excludes all
    paths, database settings, `scheduler.max_concurrent_runs`,
    `logging.retained_files`, and the entire adapter catalog, but changes for
    retry, process, protocol, or stderr-limit values. The three policy values
    are present and asserted as fixed `false`; their `Literal[False]` types
    deliberately make a valid sensitivity mutation impossible.
14. Snapshot bytes and both hashes are deterministic under TOML key ordering.
    Every public snapshot/hash entry point reconstructs and revalidates a
    defensive `ApplicationConfig` copy before projection, so mutation through
    a shallow-frozen nested metadata dictionary cannot bypass the bounds or
    secret-like key guard. Direct `ConfigSnapshot.model_validate(...)` and
    `model_validate_json(...)` calls independently reparse the embedded
    `ApplicationConfig`, require exact canonical JSON text, enforce its UTF-8
    byte ceiling, and recompute both hashes in one after-validator. Negative
    tests mutate each derived field and require stable errors without input
    echo. Project 1 Stage 5, not this Task 5, adds the selected adapter/engine
    entry and remaining experiment inputs to the final material hash.

- [ ] **Step 2: Run the configuration tests red**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\configuration -q
```

Expected: collection fails because the three configuration modules do not
exist.

- [ ] **Step 3: Apply the exact Task 5 contents from Appendix A**

The exact models mirror every row of section 22.2.1. `ConfigurationLayer`
uses separately typed partial nested models, not `dict[str, object]` or a
permissive copy of `ApplicationConfig`. `CliOverrides` is a separate flat
allowlist. The loader reads only exact supplied files with `tomllib`, validates
each layer before merge, and converts every expected parse/read/validation
failure to `ConfigurationError` with a stable code and only the exact
caller-supplied path; it does not echo file content or validation input. Path
combination is lexical and does not call
`Path.resolve()`, `Path.home()`, or `expanduser()`.

The material-base projection contains exactly:

```python
{
    "scheduler": {"retry": ...},
    "process": ...,
    "protocol": ...,
    "logging": {"max_stderr_bytes_per_invocation": ...},
    "policy": ...,
}
```

The audit projection is the complete normalized `ApplicationConfig`. Both use
closed `HashingProfile` enum members and explicit profile envelopes.
`SafeFilename` carries the reviewed serialization-schema pattern excluding
Windows-invalid characters, control characters, reserved device basenames,
and trailing dot/space. Runtime metadata carries recursive Draft 2020-12
string/integer/list/object/key bounds. Retry terminal states and identical
adapter entry objects carry `uniqueItems`; key-based adapter identity
uniqueness and deterministic entry ordering remain runtime-only because Draft
2020-12 cannot compare selected properties across array items. Aggregate depth,
aggregate nodes, encoded bytes, and normalized secret-like-key checks are also
runtime-only. The
key-name guard covers camelCase, compact, and plural sensitive spellings and
remains only a key-name defense, not value inspection.

- [ ] **Step 4: Run focused and safety checks green**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\configuration `
  tests\unit\domain\test_hashing.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= `
  tests\unit\test_package_layout.py `
  tests\safety\test_project_dependencies.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 ruff-format-all
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 ruff-check-all
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 mypy-all
git diff --check
```

Expected: all pass without creating any path below pytest `tmp_path` except
the TOML files written explicitly by the tests themselves.

- [ ] **Step 5: Independent review and commit**

The reviewers compare every field/default/bound/override against section
22.2.1 and verify no ambient source. Then:

```powershell
git add src\crypto_lab\configuration `
  tests\unit\configuration
git commit -m "feat: add strict local configuration"
```

---

### Task 6: Implement immutable dataset metadata and its named hash profile

**Files:**
- Create: `src/crypto_lab/datasets/models.py`
- Create: `src/crypto_lab/datasets/hashing.py`
- Modify: `src/crypto_lab/datasets/__init__.py`
- Create: `tests/unit/datasets/test_models.py`
- Create: `tests/unit/datasets/test_hashing.py`
- Create: `tests/property/test_dataset_hashing.py`

**Interfaces:**
- Consumes: IDs, UTC, SHA-256, `InstrumentRef`, canonical JSON, and the closed
  `DATASET_METADATA_V1` hashing profile.
- Produces: `DatasetDataType`, `DatasetValidationStatus`, `TimeInterval`,
  `RawSourceProvenance`, `DatasetPartition`, `DatasetDescriptor`,
  `dataset_metadata_hash(descriptor, partitions)`, and
  `validate_dataset_identity(descriptor, partitions)`.

- [ ] **Step 1: Write the exact dataset model and property tests from Appendix A**

The tests prove:

- inclusive start and exclusive end are strict UTC with `start < end`;
- `OHLCV` requires a normalized timeframe and every non-OHLCV Stage 3 data
  type prohibits it;
- partition IDs and ordinals are unique and exactly ordered by the descriptor;
- every partition belongs to the descriptor dataset and stays within the
  descriptor time range;
- row counts are non-negative; zero-row partitions still require ordered
  bounds and an explicit observation;
- registry-relative paths use forward slashes, contain no empty/dot/dot-dot
  segment, drive/UNC/root prefix, backslash, colon/alternate-data-stream
  syntax, Windows-invalid/control character, reserved device segment, trailing
  dot/space, NUL, or link semantics; every syntax rule is asserted against the
  final Draft 2020-12 schema while actual filesystem/link probing is deferred;
- raw/normalized checksums and content hashes are lowercase SHA-256;
- missing/duplicate intervals, diagnostics, limitations, quality observations,
  and provenance are explicit tuples with their specified uniqueness/order
  contracts; raw and normalized checksum tuples preserve partition order and
  may repeat when two valid partitions share bytes;
- validation is exactly `VALID`, `VALID_WITH_WARNINGS`, or `INVALID`;
- an invalid descriptor has at least one diagnostic; warning metadata exists
  for `VALID_WITH_WARNINGS`; clean `VALID` has neither quality interval nor
  diagnostic entries;
- unknown fields fail at every nested model;
- metadata construction performs no filesystem, environment, network,
  subprocess, database, or ingestion action.

The real Hypothesis property suite generates bounded descriptors/partitions
and proves object-key permutation invariance, partition-order sensitivity,
material-field sensitivity, deterministic round trips, and mismatch rejection.

- [ ] **Step 2: Run the dataset tests red**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\datasets `
  tests\property\test_dataset_hashing.py -q
```

Expected: collection failures for absent dataset modules.

- [ ] **Step 3: Apply the exact Task 6 contents from Appendix A**

`DatasetDescriptor` contains every section 18.1 metadata field. The
no-ingestion state represents `imported_at_utc` with Pydantic 2.12's `MISSING`
sentinel while retaining an explicit raw-source provenance tuple and
normalization declaration. `timeframe` uses the same sentinel so omission is
valid only for non-OHLCV data. Both omitted values disappear from Python/JSON
dumps and schemas; explicit null is rejected. Exactly those two declarations
carry the reviewed mypy `valid-type` suppressions required by missing PEP 661
support, and direct construction/dump/schema tests pin the behavior. The named
`dataset-metadata/v1` hash excludes descriptor identity and
operational-reference fields `dataset_id`, descriptor `content_hash`, `partition_ids`,
`diagnostic_ids`, `created_at_utc`, and `imported_at_utc`. From each ordered
partition it excludes only `partition_id`, `dataset_id`, and `relative_path`.
It includes every ordered partition `content_hash`, raw checksum, normalized
checksum, and remaining material fact, and binds that sequence through the
separately validated `partition_ids` order. It never opens a partition path;
the reviewed content hashes are inputs rather than bytes read by this function.

- [ ] **Step 4: Run focused and broader checks green**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\datasets `
  tests\property\test_dataset_hashing.py `
  tests\unit\domain\test_hashing.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= `
  tests\architecture\test_domain_import_boundary.py `
  tests\unit\test_package_layout.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 ruff-format-all
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 ruff-check-all
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 mypy-all
git diff --check
```

- [ ] **Step 5: Independent review and commit**

The reviewers compare every field with sections 11.3 and 18, verify the named
hash exclusions, and confirm that no Project 2 ingestion behavior entered.
Then:

```powershell
git add src\crypto_lab\datasets tests\unit\datasets `
  tests\property\test_dataset_hashing.py
git commit -m "feat: add dataset metadata contracts"
```

---

### Task 7: Generate and package the exact Stage 3 schema set

**Files:**
- Create: `src/crypto_lab/schema_registry.py`
- Create: `scripts/generate_schemas.py`
- Create: `scripts/verify_schema_distribution.py`
- Modify: `pyproject.toml`
- Modify: `tests/unit/test_package_layout.py`
- Create: `tests/safety/test_stage3_boundaries.py`
- Create: `tests/unit/test_schema_registry.py`
- Create: `tests/integration/test_schema_distribution.py`
- Create: the 11 generated `schemas/**` files in the fixed registry table

**Interfaces:**
- Produces: closed `SCHEMA_DEFINITIONS`; deterministic
  `render_schema_files()`; explicit-output check/write CLI; exact wheel/sdist
  byte verifier; complete Stage 3 import/source/scope guards; and repository
  Ruff/mypy scopes expanded to the newly introduced Python scripts.
- Consumes: every Stage 3 public top-level model and the
  `ArtifactOwnerRef` `TypeAdapter`.

- [ ] **Step 1: Write the schema, import, source, and distribution tests red**

Apply the exact Appendix A changes to the fresh-process import test. Pytest is
already a launcher-controlled process. Its test starts the repository
`.venv`'s exact `sys.executable -I -B` descendant in `tmp_path`, imports only
standard-library guard machinery, installs every guard, and only then imports
the listed project modules and their Pydantic dependency. The `os.getenv`
guard returns `__all__` only for the exact `pydantic.plugin._loader` caller and
rejects every other query without reading the environment; `os.environ` fails
closed. The child prints one sentinel; the parent requires zero exit, exact
stdout, empty stderr, and an untouched `tmp_path`.

The new safety scanner parses every `src/crypto_lab/**/*.py` file and rejects
imports of real engines, exchanges, networking clients, `socket`, `urllib`,
`http.client`, `subprocess`, `sqlite3`, SQLAlchemy, Alembic, pickle, YAML,
PyArrow, and dataframe libraries. It separately rejects environment/profile/
credential access and later-stage class/function names. It allows only
Pydantic plus the standard-library modules explicitly used in this stage.

Appendix A.8 displays the cumulative final
`tests/safety/test_stage3_boundaries.py` bytes after Task 8. In Task 7, create
the independently executable baseline with exactly this complete content:

```python
"""Enforce the Stage 3 architectural, source, schema, and verifier boundary."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from crypto_lab.schema_registry import SCHEMA_DEFINITIONS

_ALLOWED_SOURCE_FILES = {
    "__init__.py",
    "adapters/__init__.py",
    "adapters/descriptors.py",
    "adapters/versioning.py",
    "artifacts/__init__.py",
    "artifacts/ownership.py",
    "audit/__init__.py",
    "capabilities/__init__.py",
    "cli/__init__.py",
    "cli/__main__.py",
    "cli/main.py",
    "configuration/__init__.py",
    "configuration/loader.py",
    "configuration/models.py",
    "configuration/snapshot.py",
    "datasets/__init__.py",
    "datasets/hashing.py",
    "datasets/models.py",
    "domain/__init__.py",
    "domain/base.py",
    "domain/canonical_json.py",
    "domain/diagnostics.py",
    "domain/financial.py",
    "domain/hashing.py",
    "domain/identifiers.py",
    "domain/records.py",
    "domain/time.py",
    "domain/versioning.py",
    "experiments/__init__.py",
    "persistence/__init__.py",
    "process_supervision/__init__.py",
    "schema_registry.py",
    "strategy/__init__.py",
}
_ALLOWED_IMPORT_ROOTS = {
    "__future__",
    "argparse",
    "collections",
    "crypto_lab",
    "dataclasses",
    "datetime",
    "decimal",
    "enum",
    "hashlib",
    "importlib",
    "json",
    "pathlib",
    "pydantic",
    "re",
    "tomllib",
    "typing",
    "uuid",
}
_FORBIDDEN_AMBIENT_NAMES = {
    "os.environ",
    "os.getenv",
    "os.putenv",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    "os.startfile",
    "os.system",
    "os.unsetenv",
    "pathlib.Path.cwd",
    "pathlib.Path.expanduser",
    "pathlib.Path.home",
}
_DEFERRED_DEFINITIONS = {
    "AdapterCatalog",
    "AdapterCatalogEntry",
    "AdapterCommand",
    "AdapterCommandRequestEnvelope",
    "AdapterResultManifest",
    "AdapterValidationResult",
    "ApproximationDeclaration",
    "ArtifactFinalizationPurpose",
    "ArtifactFinalizer",
    "ArtifactOwnerKind",
    "ArtifactRef",
    "ArtifactRepository",
    "ArtifactSourceRole",
    "AuditSink",
    "AuditEvent",
    "BootstrapDescriptorEnvelope",
    "CancellationToken",
    "CandidateArtifact",
    "CandidateArtifactRepository",
    "CandidateArtifactState",
    "CandidateArtifactProducerKind",
    "CandidateFinalization",
    "CanonicalFill",
    "CanonicalOrder",
    "CapabilityDeclaration",
    "CapabilityRequirement",
    "CapabilityVocabulary",
    "CommandInvocationRecord",
    "CommandInvocationRepository",
    "CommandInvocationState",
    "CommandKind",
    "CommandResult",
    "ComparisonEligibilityResult",
    "ComparisonEligibilityService",
    "ComparisonLevel",
    "CompatibilityPolicy",
    "CompatibilityResolver",
    "CompatibilityOutcome",
    "CompatibilityResult",
    "ContentHasher",
    "Clock",
    "DatasetRepository",
    "EngineRunRecord",
    "EngineRunRepository",
    "EngineRunRequest",
    "EquityPoint",
    "EvidenceFinalizationRequest",
    "ExperimentRecord",
    "ExperimentRepository",
    "ExperimentSpec",
    "Fee",
    "FinalizationResult",
    "NegotiationResult",
    "MetricValue",
    "MonotonicInstant",
    "OrderSide",
    "OrderType",
    "PortfolioSnapshot",
    "PositionSnapshot",
    "PositionEffect",
    "ProcessSupervisor",
    "ProtocolEventEnvelope",
    "ResultFinalizationRequest",
    "RetryPolicy",
    "Result",
    "RunEvent",
    "RunManifest",
    "RuntimeAvailabilityObservation",
    "SanitizedAdapterResultManifest",
    "SemanticStatus",
    "StrategyLoader",
    "StrategySpec",
    "StrategyVersion",
    "UnitOfWork",
    "ValidationOutcome",
    "ingest_dataset",
    "negotiate_protocol",
    "normalize_dataset",
    "place_order",
}


def _qualified_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value)
        return None if parent is None else f"{parent}.{node.attr}"
    return None


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.partition(".")[0]
                aliases[bound] = alias.name if alias.asname else bound
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            for alias in node.names:
                if alias.name == "*":
                    continue
                bound = alias.asname or alias.name
                aliases[bound] = f"{node.module}.{alias.name}"
    return aliases


def _resolved_qualified_name(
    node: ast.AST,
    aliases: dict[str, str],
) -> str | None:
    name = _qualified_name(node)
    if name is None:
        return None
    head, separator, tail = name.partition(".")
    resolved = aliases.get(head, head)
    return resolved if not separator else f"{resolved}.{tail}"


def _source_files(repository_root: Path) -> tuple[Path, ...]:
    return tuple(sorted((repository_root / "src/crypto_lab").rglob("*.py")))


def test_stage3_source_file_set_is_closed(repository_root: Path) -> None:
    source = repository_root / "src/crypto_lab"
    actual = {
        path.relative_to(source).as_posix() for path in _source_files(repository_root)
    }
    assert actual == _ALLOWED_SOURCE_FILES


def test_source_imports_only_the_explicit_stage3_allowlist(
    repository_root: Path,
) -> None:
    failures: list[str] = []
    for path in _source_files(repository_root):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                modules.append(node.module)
            for module in modules:
                root = module.partition(".")[0]
                if root not in _ALLOWED_IMPORT_ROOTS:
                    failures.append(f"{path}: import root is not allowed: {module}")
    assert failures == []


def test_source_has_no_ambient_access_or_later_stage_definitions(
    repository_root: Path,
) -> None:
    failures: list[str] = []
    for path in _source_files(repository_root):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        aliases = _import_aliases(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Name | ast.Attribute):
                name = _resolved_qualified_name(node, aliases)
                if name in _FORBIDDEN_AMBIENT_NAMES:
                    failures.append(f"{path}: forbidden ambient access {name}")
            if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
                if node.name in _DEFERRED_DEFINITIONS:
                    failures.append(f"{path}: later-stage definition {node.name}")
    assert failures == []


def test_alias_resolution_cannot_hide_ambient_access() -> None:
    tree = ast.parse(
        "import os as operating\n"
        "from pathlib import Path as LocalPath\n"
        "operating.getenv('name')\n"
        "LocalPath.home()\n"
    )
    aliases = _import_aliases(tree)
    resolved = {
        name
        for node in ast.walk(tree)
        if isinstance(node, ast.Name | ast.Attribute)
        and (name := _resolved_qualified_name(node, aliases)) is not None
    }
    assert "os.getenv" in resolved
    assert "pathlib.Path.home" in resolved


@pytest.mark.parametrize("name", sorted(_DEFERRED_DEFINITIONS))
def test_each_normative_deferred_symbol_is_detected_by_the_stage3_guard(
    name: str,
) -> None:
    keyword = "class" if name[0].isupper() else "def"
    tree = ast.parse(
        f"{keyword} {name}:\n    pass\n"
        if keyword == "class"
        else f"def {name}():\n    pass\n"
    )
    defined = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
    }
    assert defined & _DEFERRED_DEFINITIONS == {name}


@pytest.mark.parametrize(
    "name",
    [
        "AdapterResultManifest",
        "CandidateArtifactState",
        "CanonicalOrder",
        "CommandInvocationState",
        "EngineRunRequest",
        "PortfolioSnapshot",
        "ValidationOutcome",
    ],
)
def test_representative_later_stage_type_mutations_are_blocked(name: str) -> None:
    tree = ast.parse(f"class {name}:\n    pass\n")
    later = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
        and node.name in _DEFERRED_DEFINITIONS
    }
    assert later == {name}


def test_schema_registry_is_closed_and_protocol_descriptors_are_located_correctly() -> (
    None
):
    paths = tuple(
        definition.relative_path.as_posix() for definition in SCHEMA_DEFINITIONS
    )
    identifiers = tuple(definition.schema_id for definition in SCHEMA_DEFINITIONS)
    assert len(paths) == 11
    assert len(paths) == len(set(paths))
    assert len(identifiers) == len(set(identifiers))
    assert "protocol/engine-descriptor-v1.schema.json" in paths
    assert "protocol/adapter-descriptor-v1.schema.json" in paths
    assert all(not path.startswith("adapters/") for path in paths)
    assert all("semantic-version" not in path for path in paths)


def test_gitnexus_remains_disabled_with_evidence(repository_root: Path) -> None:
    outcome = (repository_root / "tools/gitnexus/outcome.json").read_text(
        encoding="utf-8"
    )
    assert '"outcome": "DISABLED_WITH_EVIDENCE"' in outcome
```

This is the complete Task 7 file, not an omission recipe. It has no verifier
hash, parser, mutation, or exact-order assertion. Task 8 applies its exact
unified patch to these bytes before testing or replacing the verifier.

Schema tests require exactly the 11 registry paths/URNs, Draft 2020-12 meta
schema, `Draft202012Validator.check_schema`, strict extra-field rejection,
string-only Decimal schemas, UTC `Z` constraints, all six owner branches, and
descriptor schemas under `schemas/protocol`. Exact negative parity tests cover
all schema-expressible Stage 3 invariants: unique arrays, zero-row observation,
dataset data-type/timeframe and validation-status conditionals, Diagnostic
correlation/category requirements, configuration retry/entry uniqueness, and
descriptor collection uniqueness.
Ordering, interval arithmetic, venue/instrument equality, cross-array
disjointness, key-based adapter identity equality, aggregate recursive
depth/node/encoded-byte limits, and
cross-record dataset/checksum/ordinal/provenance identity remain runtime-only
because Draft 2020-12 cannot express them soundly. They generate into `tmp_path`,
compare byte-for-byte, detect a mutated/missing/unexpected file, and prove no
I/O happens when the production registry is imported. Exact source review and
the import-purity boundary scan separately require both script modules to keep
all I/O behind explicit `main(...)`/helper calls; their ordinary pytest imports
are not misrepresented as a guarded fresh-process proof.

Distribution tests create controlled wheel/sdist archives in `tmp_path` and
prove the verifier accepts exactly one copy at these locations:

```text
wheel: crypto_lab/schemas/<registry-relative-path>
sdist: crypto_trading_lab-0.1.0/schemas/<registry-relative-path>
```

Missing, duplicate, root-level wheel, wrong-byte, and every unexpected payload
beneath either schema prefix must fail.

- [ ] **Step 2: Run the tests red**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= `
  tests\unit\test_schema_registry.py `
  tests\integration\test_schema_distribution.py `
  tests\safety\test_stage3_boundaries.py `
  tests\unit\test_package_layout.py -q
```

Expected: absent registry/scripts/schema paths and missing import tuple entries.

- [ ] **Step 3: Apply the exact registry, scripts, packaging, and safety contents from Appendix A**

`scripts/generate_schemas.py` requires `--output <path>` plus exactly one of
`--check` or `--write`; it has no default output and performs no import-time
I/O. Every generated target is a lexical descendant of the explicit output
path. The generator rejects a symlink output root and every existing symlink
entry, but does not claim to defeat a pre-existing symlink or reparse-point
ancestor; execution supplies the reviewed repository `schemas/` root, and
physical filesystem containment remains Stage 7 work. `--check` never writes
and returns nonzero for any missing, changed, or unexpected file.

Every schema is produced with Pydantic serialization mode, then receives the
exact `$schema` and `$id`, and is serialized with canonical JSON plus one LF.
The owner schema comes directly from `TypeAdapter(ArtifactOwnerRef)`. No
semantic-version schema or wrapper-owner schema is generated.

Apply these exact Hatch/Ruff changes:

```toml
[tool.hatch.build.targets.wheel.force-include]
"schemas" = "crypto_lab/schemas"
```

Add `"/schemas"` once to the existing sdist include list. Change Ruff
`src = ["src", "tests"]` to `src = ["src", "tests", "scripts"]` and mypy
`files = ["src", "tests"]` to `files = ["src", "tests", "scripts"]`. The
target-free launcher command remains byte-stable: `python -I -B -m mypy` reads
the first repository-owned mypy scope through Task 6 and the expanded scope
from this task onward. Do not add a second wheel include rule, copy schemas into
`src`, include `/tools`, or add caller-selected mypy targets.

- [ ] **Step 4: Generate the source schemas and prove deterministic checks**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 schema-generate-write
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 schema-generate-check
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= `
  tests\unit\test_schema_registry.py `
  tests\integration\test_schema_distribution.py `
  tests\safety\test_stage3_boundaries.py `
  tests\unit\test_package_layout.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 ruff-format-all
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 ruff-check-all
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 mypy-all
git diff --check
```

Expected: exactly 11 generated files; all schemas valid and byte-stable; all
tests and static checks pass.

- [ ] **Step 5: Build offline and verify exact distribution contents**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 build
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 schema-distribution
```

Expected: one wheel and one sdist are found; each contains exactly one copy of
all 11 schema bytes in its required location; no schema is absent, duplicated,
or unexpected. Build output remains ignored and is never staged.

- [ ] **Step 6: Independent review and commit**

Reviewers inspect the expanded repository-owned Ruff/mypy scopes, every
generated schema, and all package/archive paths. Then:

```powershell
git add pyproject.toml src\crypto_lab\schema_registry.py `
  scripts\generate_schemas.py scripts\verify_schema_distribution.py `
  tests\unit\test_package_layout.py `
  tests\safety\test_stage3_boundaries.py `
  tests\unit\test_schema_registry.py `
  tests\integration\test_schema_distribution.py schemas
git commit -m "build: generate canonical stage 3 schemas"
```

---

### Task 8: Make ordinary verification schema-complete and independently offline

**Files:**
- Modify: `tests/safety/test_stage3_boundaries.py`
- Modify: `scripts/verify.ps1`
- Modify: `docs/development/verification.md`
- Modify: `README.md`

**Interfaces:**
- Produces: one ten-operation offline verifier whose schema source and built
  distribution checks cannot be skipped by an ordinary completion claim.

- [ ] **Step 1: Add the exact verifier-contract test from Appendix A**

Apply this exact additive patch to Task 7's baseline
`tests/safety/test_stage3_boundaries.py`. Imports go immediately after `ast` in
the displayed Ruff order; constants go after `_DEFERRED_DEFINITIONS` and before
`_qualified_name`; helpers go after `_source_files` and before the first source
test; and tests go after the schema-registry-location test and before the
GitNexus test. The result must equal the cumulative final Appendix A.8 body
byte-for-byte:

```diff
--- a/tests/safety/test_stage3_boundaries.py
+++ b/tests/safety/test_stage3_boundaries.py
@@ -5,0 +6,4 @@
+import hashlib
+import json
+import shutil
+import subprocess
@@ -165,0 +170,24 @@
+_EXPECTED_VERIFICATION_PROFILES = (
+    ("lock-check",),
+    ("sync",),
+    ("ruff-format-all",),
+    ("ruff-check-all",),
+    ("mypy-all",),
+    ("schema-generate-check",),
+    ("pytest-all",),
+    ("build",),
+    ("schema-distribution",),
+)
+_EXPECTED_VERIFIER_SHA256 = (
+    "4296811ae310fc7e8e17bd3b63f4c6c794a2c6e3c8d20b642de40cf918c2c4cd"
+)
+_ALLOWED_VERIFIER_COMMANDS = {
+    "Assert-NativeSuccess",
+    "Join-Path",
+    "Pop-Location",
+    "Push-Location",
+    "Resolve-Path",
+    "Write-Host",
+    "git",
+    "powershell",
+}
@@ -206,0 +235,83 @@
+
+
+def _normalized_source(path: Path) -> str:
+    lines = path.read_text(encoding="utf-8").splitlines()
+    return "\n".join(line.rstrip() for line in lines) + "\n"
+
+
+def _powershell() -> str:
+    executable = shutil.which("powershell")
+    assert executable is not None
+    return executable
+
+
+def _powershell_command_records(
+    path: Path,
+    repository_root: Path,
+) -> tuple[dict[str, str], ...]:
+    parser = (
+        "$path=[Console]::In.ReadLine();$tokens=$null;$errors=$null;"
+        "$ast=[System.Management.Automation.Language.Parser]::ParseFile("
+        "$path,[ref]$tokens,[ref]$errors);"
+        "if($errors.Count-ne 0){exit 91};"
+        "$records=@($ast.FindAll({param($node) $node -is "
+        "[System.Management.Automation.Language.CommandAst]},$true)|"
+        "ForEach-Object{$name=$_.GetCommandName();"
+        "if($null-eq$name){$name='<dynamic>'};"
+        "[pscustomobject]@{name=$name;text=$_.Extent.Text}});"
+        "$records|ConvertTo-Json -Compress"
+    )
+    completed = subprocess.run(  # noqa: S603 - reviewed fixed parser boundary
+        [_powershell(), "-NoProfile", "-Command", parser],
+        cwd=repository_root,
+        input=f"{path}\n",
+        check=False,
+        capture_output=True,
+        text=True,
+        timeout=10,
+        shell=False,
+    )
+    assert completed.returncode == 0, completed.stderr
+    decoded = json.loads(completed.stdout)
+    records = [decoded] if isinstance(decoded, dict) else decoded
+    assert isinstance(records, list)
+    assert all(isinstance(record, dict) for record in records)
+    return tuple(records)
+
+
+def _normalized_extent(text: str) -> str:
+    return " ".join(text.replace("`", "").split())
+
+
+def _verifier_profiles(
+    records: tuple[dict[str, str], ...],
+) -> tuple[tuple[str, ...], ...]:
+    profiles: list[tuple[str, ...]] = []
+    for record in records:
+        if record["name"].casefold() != "powershell":
+            continue
+        tokens = _normalized_extent(record["text"]).split()
+        launcher_index = next(
+            index
+            for index, token in enumerate(tokens)
+            if token.casefold().endswith("scripts\\invoke-uv.ps1")
+        )
+        profiles.append(tuple(tokens[launcher_index + 1 :]))
+    return tuple(profiles)
+
+
+def _verifier_is_exactly_closed(path: Path, repository_root: Path) -> bool:
+    digest = hashlib.sha256(_normalized_source(path).encode()).hexdigest()
+    records = _powershell_command_records(path, repository_root)
+    commands = {record["name"] for record in records}
+    return (
+        digest == _EXPECTED_VERIFIER_SHA256
+        and commands == _ALLOWED_VERIFIER_COMMANDS
+        and _verifier_profiles(records) == _EXPECTED_VERIFICATION_PROFILES
+        and tuple(
+            _normalized_extent(record["text"])
+            for record in records
+            if record["name"].casefold() == "git"
+        )
+        == ("& git diff --check",)
+    )
@@ -328,0 +440,35 @@
+def test_complete_verifier_has_exact_offline_order(repository_root: Path) -> None:
+    verifier = repository_root / "scripts" / "verify.ps1"
+    assert _verifier_is_exactly_closed(verifier, repository_root)
+
+
+@pytest.mark.parametrize(
+    ("injected", "expected_ast_name"),
+    [
+        (
+            "bitsadmin /transfer bad https://example.invalid out",
+            "bitsadmin",
+        ),
+        (
+            "certutil -urlcache -split -f https://example.invalid out",
+            "certutil",
+        ),
+        ("[System.Net.Http.HttpClient]::new()", None),
+        ("$executable = 'uv'; & $executable --version", "<dynamic>"),
+    ],
+)
+def test_verifier_mutations_fail_exact_hash_and_ast_closure(
+    repository_root: Path,
+    tmp_path: Path,
+    injected: str,
+    expected_ast_name: str | None,
+) -> None:
+    source = _normalized_source(repository_root / "scripts" / "verify.ps1")
+    mutated = tmp_path / "mutated-verifier.ps1"
+    mutated.write_text(f"{source}{injected}\n", encoding="utf-8")
+    assert not _verifier_is_exactly_closed(mutated, repository_root)
+    if expected_ast_name is not None:
+        records = _powershell_command_records(mutated, repository_root)
+        assert expected_ast_name in {record["name"] for record in records}
+
+
```

The test parses `scripts/verify.ps1`, semantically unwraps each fixed
`powershell -File .\scripts\invoke-uv.ps1` call, and requires this exact closed
profile/git order:

```text
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
```

Together with the already-committed launcher contract tests, the safety suite
freezes the normalized verifier and launcher bodies and closes both PowerShell
AST command sets. It proves there is no plain `uv lock`, non-offline sync/build,
`uv run --frozen`, `pip`, package installation, GitNexus, Node, engine, dynamic
executable, or network command. Mutation tests append `bitsadmin`,
`certutil -urlcache`, `System.Net.HttpClient`, and an indirect executable
variable and require the closure check to fail. Keep first-failure behavior,
native exit propagation, repository-root resolution, and `finally`-based
directory restoration.

- [ ] **Step 2: Run the verifier-contract test red**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= `
  tests\safety\test_stage3_boundaries.py::test_complete_verifier_has_exact_offline_order -q
```

Expected: failure because the inherited Stage 2 verifier still has eight raw-uv
operations, its direct mypy invocation pins only `src tests` rather than using
the target-free launcher profile governed by Task 7's repository-owned
`files = ["src", "tests", "scripts"]` setting, and it lacks both schema checks.

- [ ] **Step 3: Apply the exact Task 8 patches from Appendix A**

Insert schema source checking after mypy, keep pytest after it, and insert
distribution checking immediately after the offline build. Update development
verification to list the same ten commands and add focused schema commands.
Update README's verification description and local commands without claiming
Stage 3 is complete; final status belongs to Task 9.

- [ ] **Step 4: Run focused checks and the full verifier**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= `
  tests\safety\test_stage3_boundaries.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

Required: all ten operations exit zero; schema source check is clean; all tests
pass at or above the 90 percent branch threshold; wheel/sdist build; archive
schema check passes; Git whitespace is clean. Record exact test count,
coverage, artifact names, warnings, and every command exit.

- [ ] **Step 5: Independent review and commit**

Reviewers compare script and documentation order byte-for-byte and confirm no
separate probe is required to make a later command offline. Then:

```powershell
git add tests\safety\test_stage3_boundaries.py scripts\verify.ps1 `
  docs\development\verification.md README.md
git commit -m "docs: add stage 3 verification workflow"
```

---

### Task 9: Run final acceptance, record Stage 3 status, and fast-forward main

**Files:**
- Modify: `tests/safety/test_stage3_boundaries.py`
- Modify: `tests/safety/test_gitnexus_development_tooling.py`
- Modify: `docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: the committed Tasks 1-8 implementation and all fifteen roadmap
  gates.
- Produces: fresh base-to-HEAD acceptance evidence, the exact verified
  implementation commit recorded in status, and a direct local fast-forward of
  the clean Stage 3 branch into `main`.

- [ ] **Step 1: Verify the committed implementation before any status claim**

```powershell
git status --short
$stage3BaseCommit = (git merge-base HEAD main).Trim()
if ([string]::IsNullOrWhiteSpace($stage3BaseCommit)) {
    throw "Unable to determine the Stage 3 base commit"
}
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 lock-check
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 sync
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 cli-version
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 cli-module-version
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 cli-help
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 cli-unknown
```

Required: clean status before verification; all ten verifier operations zero;
full test count and branch coverage recorded; source/distribution schema checks
clean; both artifacts built; version commands exactly `crypto-lab 0.1.0`;
help exits 0; unknown argument exits 2. If any check fails, do not edit status.

- [ ] **Step 2: Run complete manual fallback, scope, and diff review**

```powershell
rg --files src tests scripts schemas docs AGENTS.md README.md pyproject.toml
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= `
  tests\safety\test_stage3_boundaries.py `
  tests\safety\test_project_dependencies.py `
  tests\safety\test_gitnexus_development_tooling.py `
  tests\unit\test_package_layout.py -q
$sourceBoundaryHits = @(
  rg -n "os\.getenv|os\.environ|socket\.|subprocess\.|urllib\.request|http\.client|requests|httpx|aiohttp|websocket|sqlite3|sqlalchemy|alembic|pyarrow|pandas|polars|pickle|binance|ccxt|vectorbt|freqtrade|nautilus|jesse|octobot|hummingbot|quantconnect" `
    src\crypto_lab
)
if ($LASTEXITCODE -eq 0) {
    $sourceBoundaryHits | Write-Error
    throw "Forbidden Stage 3 application-source boundary hit"
}
if ($LASTEXITCODE -ne 1) {
    throw "Source boundary search failed with exit code $LASTEXITCODE"
}
git diff --name-status "$stage3BaseCommit..HEAD"
git diff --stat "$stage3BaseCommit..HEAD"
git diff --check "$stage3BaseCommit..HEAD"
git diff "$stage3BaseCommit..HEAD"
```

The scripted AST/import/dependency tests own the reviewed structural and
mutation literals, so this step has no raw test-fixture hits to classify. The
narrow source search must return exit 1 with no output; exit 0 is a blocker and
any other exit is a search failure. Confirm every changed path is in the exact
Stage 3 file map, every generated schema is reviewed, no later-stage record or
service entered, and no environment/network/process/filesystem-runtime/
database/engine behavior exists. Record this as the Stage 2 disabled manual
advisory review.

Dispatch fresh whole-stage architecture, code-quality, security, test-quality,
type-design, generated-schema, and scope reviewers against
`$stage3BaseCommit..HEAD`. Resolve every Critical or Important finding through
a new TDD correction commit. Any correction before the status edit invalidates
the current evidence: return to Step 1, rerun every command there, repeat this
entire diff/review step with fresh reviewers, and only then continue. When a
complete Step 1/Step 2 pass has no unresolved finding, capture the exact
reviewed implementation tip and verify it did not move:

```powershell
$stage3ImplementationCommit = (git rev-parse HEAD).Trim()
if ($stage3ImplementationCommit -notmatch '^[0-9a-f]{40}$') {
    throw "Stage 3 implementation commit must be a lowercase 40-character hash"
}
if ((git status --short)) {
    throw "Stage 3 worktree must be clean before status binding"
}
if ((git rev-parse HEAD).Trim() -cne $stage3ImplementationCommit) {
    throw "Stage 3 implementation tip moved after acceptance review"
}
```

Steps 3 and 4 consume this variable. They must never reuse a value captured
before a correction.

- [ ] **Step 3: Write the roadmap-status tests red**

Extend the two named safety files with exact assertions that:

- roadmap status says `Stages 1 through 3 complete`;
- Stage 3's plan label is `Approved detailed implementation plan`;
- its status row says `Approved and executed`, records the exact
  `$stage3ImplementationCommit`, and marks the exit gate `Complete`;
- Stage 4 is `Eligible for just-in-time planning after Stage 3 completion`;
- Stage 2 remains `DISABLED_WITH_EVIDENCE` and GitNexus remains optional;
- README status says `Project 1 Stages 1-3 complete`.

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= `
  tests\safety\test_stage3_boundaries.py `
  tests\safety\test_gitnexus_development_tooling.py -q
```

Expected: only the new status assertions fail because the roadmap/README still
record the pre-acceptance state.

- [ ] **Step 4: Apply the exact status patch with the captured commit**

Use `apply_patch`. Replace the roadmap header status with:

```markdown
**Status:** Approved planning decomposition; Stages 1 through 3 complete
```

Change the introductory sentence to say Stages 1 through 3 have approved
detailed implementation plans. Change only Stage 3's plan label from
`Planned detailed implementation plan` to `Approved detailed implementation
plan`. Replace the Stage 3 status row with this exact text after binding
`__STAGE3_IMPLEMENTATION_COMMIT__` to the already captured 40-character
`$stage3ImplementationCommit` value:

```markdown
| 3 — Canonical Domain, Configuration, Hashing, and Schemas | Approved and executed | Complete at `__STAGE3_IMPLEMENTATION_COMMIT__` | Complete; canonical models, explicit configuration, named hashes, dataset metadata, structural descriptors, artifact owners, and 11 generated schemas verified offline |
```

This binding is mechanical, not an unresolved design choice. Before applying
the patch, require the value to match `^[0-9a-f]{40}$`; after applying it,
require `rg -n "__STAGE3_IMPLEMENTATION_COMMIT__"` to return exit 1 with no
output.

Replace Stage 4's detailed-plan status with
`Eligible for just-in-time planning after Stage 3 completion`. In README,
replace `**Status:** Project 1 Stage 3 implementation under acceptance review`
with
`**Status:** Project 1 Stages 1-3 complete` and update only the opening scope
sentence to name the completed Stage 3 foundation. Do not change the ten-stage
order, 21 edges, 15 gates, Stage 2 outcome, any later stage scope, or the
architecture/ADR.

- [ ] **Step 5: Run focused status checks, commit, and recollect all evidence**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= `
  tests\safety\test_stage3_boundaries.py `
  tests\safety\test_gitnexus_development_tooling.py -q
git diff --check
git add tests\safety\test_stage3_boundaries.py `
  tests\safety\test_gitnexus_development_tooling.py `
  docs\superpowers\plans\2026-08-10-project-1-master-roadmap.md README.md
git diff --cached --name-status
git diff --cached --check
git diff --cached
```

Required before committing: exactly the four Task 9 files are staged; cached
whitespace is clean; and a fresh independent Task 9 specification reviewer
approves the complete staged diff. Only then run:

```powershell
git commit -m "docs: complete project 1 stage 3"
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
git diff --check "$stage3BaseCommit..HEAD"
git diff --name-status "$stage3BaseCommit..HEAD"
git diff --stat "$stage3BaseCommit..HEAD"
git diff "$stage3BaseCommit..HEAD"
git status --short
```

Required: focused tests green; the status commit contains exactly four files;
fresh full verifier green after the commit; complete base-to-HEAD diff clean;
feature worktree clean; and fresh independent whole-stage architecture,
code-quality, security, test-quality, type-design, generated-schema, and scope
reviewers approve the committed base-to-HEAD result.

If a post-status finding needs only Task 9 documentation/test correction, make
a narrow independently reviewed correction commit, then repeat every command
and every fresh reviewer in this step. If a post-status finding changes any
implementation, generated schema, dependency, launcher, verifier, or other
Tasks 1-8 behavior, use TDD where production behavior is involved, create the
independently reviewed correction commit, set
`$stage3ImplementationCommit = (git rev-parse HEAD).Trim()`, and return through
the complete Step 1/Step 2 verification, diff, and fresh-review loop. Then make
a separate roadmap-binding commit that changes only the roadmap row and the
`STAGE3_IMPLEMENTATION_COMMIT` test constant to that new exact hash:

First update only the test constant to the new hash and run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 pytest-focused -o addopts= `
  tests\safety\test_stage3_boundaries.py `
  tests\safety\test_gitnexus_development_tooling.py -q
```

Required RED evidence: the focused status test fails specifically because the
roadmap still names the preceding implementation commit. Do not edit the
roadmap before recording that failure. Then mechanically replace only the
roadmap Stage 3 commit binding with the new hash and rerun the same focused
command. Required GREEN evidence: both status files pass. Only after that
red/green sequence run:

```powershell
git add docs\superpowers\plans\2026-08-10-project-1-master-roadmap.md `
  tests\safety\test_stage3_boundaries.py
git diff --cached --name-status
git diff --cached --check
git diff --cached
git commit -m "docs: rebind project 1 stage 3 evidence"
```

The focused status tests must be red against the stale roadmap after the test
constant changes, then green only after the roadmap binding changes;
the staged diff must contain exactly those two paths and receive a fresh Task 9
review. After the rebind commit, repeat this step's full verifier, complete
base-to-HEAD diff, and all whole-stage reviewers. Another implementation
correction repeats the same correction/review/rebind loop; a documentation-only
correction repeats the final step review. Narrow correction commits are
allowed, every correction appears in the base-to-HEAD diff, and no empty
verification commit is created.

Immediately before merge, require the current status test to pass and require
the roadmap/test binding still to name the tracked implementation commit:

```powershell
$roadmapPattern = "Complete at ``$stage3ImplementationCommit``"
$bindingPattern = 'STAGE3_IMPLEMENTATION_COMMIT = "' + $stage3ImplementationCommit + '"'
$roadmapBinding = @(
  rg -n -F -- $roadmapPattern `
    docs\superpowers\plans\2026-08-10-project-1-master-roadmap.md
)
$testBinding = @(
  Select-String `
    -LiteralPath tests\safety\test_stage3_boundaries.py `
    -SimpleMatch `
    -CaseSensitive `
    -Pattern $bindingPattern
)
if ($roadmapBinding.Count -ne 1 -or $testBinding.Count -ne 1) {
    throw "Stage 3 status evidence is stale"
}
```

Merge begins only after this binding check and all final reviews are clean.

- [ ] **Step 6: Fast-forward local main under the standing integration policy**

From the main checkout, require clean `main` still at `$stage3BaseCommit`, then:

```powershell
git status --short
git branch --show-current
git rev-parse HEAD
git merge --ff-only project-1-stage-3-domain-configuration
git rev-parse HEAD
git status --short
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
git merge-base --is-ancestor `
  project-1-stage-3-domain-configuration `
  main
```

Required: fast-forward exit zero; no merge commit; merged main exactly equals
feature HEAD; all ten merged-main operations pass; main is clean; ancestry
check exits zero. Do not fetch, pull, push, rebase, squash, amend, create a PR,
delete the external worktree/branch, invoke GitNexus, or begin Stage 4
implementation. If main is not clean or no longer equals `$stage3BaseCommit`,
stop without reconciling it automatically.

- [ ] **Step 7: Apply the bounded rollback rule if integration evidence fails**

Before the fast-forward, any failure leaves `main` unchanged. A failed
`git merge --ff-only` also requires no rollback. If and only if the
fast-forward succeeded but merged-main verification then fails, preserve the
feature branch and worktree, record the failing operation, and stop for a
specific user ruling. Do not reset or force-update `main`. If the user approves
history-preserving rollback, run from clean `main`:

```powershell
git revert --no-commit "$stage3BaseCommit..HEAD"
git diff --check
git status --short
git commit -m "revert: roll back project 1 stage 3"
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

Review the complete staged inverse before the revert commit. If revert
application conflicts, run `git revert --abort`, leave all refs intact, and
return the conflict evidence to the user. Never improvise a reset, rebase,
squash, or branch deletion as recovery.

---

## Acceptance and handoff checklist

Stage 3 is eligible for a completion claim only when the Task 9 evidence proves
all of the following in the implementation worktree and again on merged local
`main`:

- Task 1 has recorded prerequisite launcher inspection and green contract
  evidence for all 21 exact closed launcher operation vectors before dependency
  work; Tasks 2 through 9 have recorded red and
  focused green evidence; every task has independent specification review and
  its required code/security review;
- the complete verifier reports ten successful operations, the exact test
  count, branch coverage at or above the configured gate, one successful wheel,
  one successful sdist, and clean schema-distribution bytes;
- `render_schema_files()` and the source tree contain exactly the 11 registered
  schema paths and IDs, with no external `$ref`, duplicate path, duplicate ID,
  stale generated schema, or second wheel/sdist copy;
- `git diff --name-status "$stage3BaseCommit..HEAD"` is a subset of the exact
  Stage 3 file map and neither the architecture specification nor ADR 0001
  changed;
- source/import/AST/manual scans find no engine, exchange, live trading,
  network client, credentials, ambient configuration, subprocess, database,
  ingestion, normalization, persistence, orchestration, finalization, or
  later-stage record behavior;
- the roadmap still contains ten stages, 21 dependency edges, and 15 global
  gates; only the Stage 3 status, its detailed-plan label, and Stage 4 planning
  eligibility changed;
- Stage 2 remains `DISABLED_WITH_EVIDENCE`; no GitNexus package,
  configuration, MCP entry, index, wrapper, invocation, or dependency appears;
- every ordinary operation uses a closed launcher profile whose uv vector is
  offline (and, for tool execution, also `run --no-sync --no-env-file`), and only the
  two separately approved Task 1 bootstrap commands can omit `--offline`;
- every human-invoked ordinary lock check, synchronization, Python tool, CLI,
  schema, and build command after Task 1 launcher creation enters through
  `scripts/invoke-uv.ps1`; the raw uv forms listed in verifier semantics are
  synthesized internally and are not documentation bypasses;
- the implementation and merged-main worktrees are clean, the merge is a
  direct fast-forward, no remote operation or pull request occurred, the
  feature branch/worktree remain available, and Stage 4 has not begun.

The controller returns the captured base, implementation, status, feature-head,
and final-main commit hashes; per-task and total diff statistics; all verifier
operation exit codes; tests/coverage/build/schema evidence; reviewer outcomes;
network-gate usage; and any warning or skipped check. Any absent item leaves
Stage 3 blocked rather than partially accepted.

---

## Appendix A: Authoritative exact text changes

The contents and patches in this appendix are normative for implementation.
Apply every displayed text file exactly; any semantic or layout deviation
requires a reviewed correction to this plan. `uv.lock`
and the 11 JSON Schemas are the only generated files whose bytes are produced
by the exact commands instead of copied from this appendix.

### A.1 Domain primitive files

Create `src/crypto_lab/domain/base.py` with exactly:

```python
"""Strict immutable base classes for canonical Project 1 records."""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict

SCHEMA_VERSION = "1.0.0"


class CanonicalModel(BaseModel):
    """Reject coercion, mutation, unknown fields, and invalid defaults."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
        validate_default=True,
    )
```

Create `src/crypto_lab/domain/identifiers.py` with exactly:

```python
"""Validated canonical identifiers and normalized names."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from pydantic import AfterValidator, StringConstraints, WithJsonSchema
from pydantic.json_schema import JsonSchemaValue

_UUID4 = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"


def exact_string_schema(
    runtime_pattern: str,
    *,
    min_length: int | None = None,
    max_length: int | None = None,
) -> JsonSchemaValue:
    """Return a string schema whose pattern has an absolute ECMA-compatible end."""
    if not runtime_pattern.endswith("$"):
        raise ValueError("runtime pattern must end with '$'")
    schema: JsonSchemaValue = {
        "type": "string",
        "pattern": runtime_pattern[:-1] + r"(?![\s\S])",
    }
    if min_length is not None:
        schema["minLength"] = min_length
    if max_length is not None:
        schema["maxLength"] = max_length
    return schema


def validate_prefixed_uuid4(value: str, prefix: str) -> str:
    """Return one exact lowercase canonical prefixed UUID4."""
    if not value.startswith(prefix):
        raise ValueError(f"identifier must start with {prefix!r}")
    suffix = value.removeprefix(prefix)
    parsed = UUID(suffix)
    if parsed.version != 4 or str(parsed) != suffix:
        raise ValueError("identifier must contain a lowercase canonical UUID4")
    return value


def _experiment_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "exp_")


def _run_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "run_")


def _artifact_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "art_")


def _dataset_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "ds_")


def _strategy_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "strat_")


def _strategy_version_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "strv_")


def _invocation_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "inv_")


def _event_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "evt_")


def _candidate_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "cand_")


def _diagnostic_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "diag_")


def _audit_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "audit_")


def _partition_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "part_")


type ExperimentId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^exp_{_UUID4}$"),
    AfterValidator(_experiment_id),
    WithJsonSchema(exact_string_schema(rf"^exp_{_UUID4}$")),
]
type RunId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^run_{_UUID4}$"),
    AfterValidator(_run_id),
    WithJsonSchema(exact_string_schema(rf"^run_{_UUID4}$")),
]
type ArtifactId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^art_{_UUID4}$"),
    AfterValidator(_artifact_id),
    WithJsonSchema(exact_string_schema(rf"^art_{_UUID4}$")),
]
type DatasetId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^ds_{_UUID4}$"),
    AfterValidator(_dataset_id),
    WithJsonSchema(exact_string_schema(rf"^ds_{_UUID4}$")),
]
type StrategyId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^strat_{_UUID4}$"),
    AfterValidator(_strategy_id),
    WithJsonSchema(exact_string_schema(rf"^strat_{_UUID4}$")),
]
type StrategyVersionId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^strv_{_UUID4}$"),
    AfterValidator(_strategy_version_id),
    WithJsonSchema(exact_string_schema(rf"^strv_{_UUID4}$")),
]
type InvocationId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^inv_{_UUID4}$"),
    AfterValidator(_invocation_id),
    WithJsonSchema(exact_string_schema(rf"^inv_{_UUID4}$")),
]
type EventId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^evt_{_UUID4}$"),
    AfterValidator(_event_id),
    WithJsonSchema(exact_string_schema(rf"^evt_{_UUID4}$")),
]
type CandidateArtifactId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^cand_{_UUID4}$"),
    AfterValidator(_candidate_id),
    WithJsonSchema(exact_string_schema(rf"^cand_{_UUID4}$")),
]
type DiagnosticId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^diag_{_UUID4}$"),
    AfterValidator(_diagnostic_id),
    WithJsonSchema(exact_string_schema(rf"^diag_{_UUID4}$")),
]
type AuditEventId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^audit_{_UUID4}$"),
    AfterValidator(_audit_id),
    WithJsonSchema(exact_string_schema(rf"^audit_{_UUID4}$")),
]
type DatasetPartitionId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^part_{_UUID4}$"),
    AfterValidator(_partition_id),
    WithJsonSchema(exact_string_schema(rf"^part_{_UUID4}$")),
]
type Sha256 = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$"),
    WithJsonSchema(exact_string_schema(r"^[0-9a-f]{64}$")),
]
type NormalizedIdentifier = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    ),
    WithJsonSchema(
        exact_string_schema(
            r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
            min_length=1,
            max_length=128,
        )
    ),
]
type AssetCode = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=32,
        pattern=r"^[A-Z][A-Z0-9]*(?:[._-][A-Z0-9]+)*$",
    ),
    WithJsonSchema(
        exact_string_schema(
            r"^[A-Z][A-Z0-9]*(?:[._-][A-Z0-9]+)*$",
            min_length=1,
            max_length=32,
        )
    ),
]
```

Create `src/crypto_lab/domain/time.py` with exactly:

```python
"""Canonical timezone-aware UTC values."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Annotated

from pydantic import BeforeValidator, PlainSerializer, ValidationInfo, WithJsonSchema

_UTC_PATTERN = (
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{6})?Z$"
)
_UTC_SCHEMA_PATTERN = _UTC_PATTERN[:-1] + r"(?![\s\S])"
_UTC_SCHEMA = {
    "type": "string",
    "format": "date-time",
    "pattern": _UTC_SCHEMA_PATTERN,
}


def require_utc(value: datetime) -> datetime:
    """Accept UTC only and reject naive or nonzero-offset values."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError("timestamp offset must be UTC")
    return value.astimezone(UTC)


def format_utc(value: datetime) -> str:
    """Serialize UTC with Z and deterministic fractional seconds."""
    normalized = require_utc(value)
    timespec = "seconds" if normalized.microsecond == 0 else "microseconds"
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


def parse_utc(value: object, info: ValidationInfo) -> datetime:
    """Accept typed UTC datetimes in Python and canonical Z text in JSON."""
    if info.mode == "python":
        if not isinstance(value, datetime):
            raise ValueError("Python input must be a datetime")
        return require_utc(value)
    if not isinstance(value, str) or re.fullmatch(_UTC_PATTERN, value) is None:
        raise ValueError("JSON timestamp is not canonical UTC text")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise ValueError("JSON timestamp is not a valid datetime") from error
    return require_utc(parsed)


type UtcDateTime = Annotated[
    datetime,
    BeforeValidator(parse_utc),
    PlainSerializer(format_utc, return_type=str, when_used="json"),
    WithJsonSchema(_UTC_SCHEMA, mode="validation"),
    WithJsonSchema(_UTC_SCHEMA, mode="serialization"),
]
```

Create `src/crypto_lab/domain/financial.py` with exactly:

```python
"""Canonical Decimal validation and fixed-point serialization."""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Annotated

from pydantic import (
    AfterValidator,
    BeforeValidator,
    PlainSerializer,
    ValidationInfo,
    WithJsonSchema,
)

MAX_DECIMAL_TEXT_LENGTH = 256
CANONICAL_DECIMAL_PATTERN = (
    r"^(?:0|[1-9][0-9]*(?:\.[0-9]*[1-9])?|0\.[0-9]*[1-9]|"
    r"-[1-9][0-9]*(?:\.[0-9]*[1-9])?|-0\.[0-9]*[1-9])$"
)
POSITIVE_DECIMAL_PATTERN = r"^(?:[1-9][0-9]*(?:\.[0-9]*[1-9])?|0\.[0-9]*[1-9])$"
NON_NEGATIVE_DECIMAL_PATTERN = r"^(?:0|[1-9][0-9]*(?:\.[0-9]*[1-9])?|0\.[0-9]*[1-9])$"


def format_decimal(value: Decimal) -> str:
    """Render a finite Decimal without ambient-context normalization."""
    if not value.is_finite():
        raise ValueError("decimal must be finite")
    if value.is_zero():
        if value.is_signed():
            raise ValueError("negative zero is forbidden")
        return "0"
    sign, raw_digits, raw_exponent = value.as_tuple()
    if not isinstance(raw_exponent, int):
        raise ValueError("decimal must be finite")
    trailing_zeroes = 0
    for digit in reversed(raw_digits):
        if digit != 0:
            break
        trailing_zeroes += 1
    significant_digits = (
        raw_digits[:-trailing_zeroes] if trailing_zeroes else raw_digits
    )
    exponent = raw_exponent + trailing_zeroes
    coefficient_length = len(significant_digits)
    if exponent >= 0:
        body_length = coefficient_length + exponent
    else:
        point = coefficient_length + exponent
        body_length = (
            2 - point + coefficient_length if point <= 0 else coefficient_length + 1
        )
    if sign + body_length > MAX_DECIMAL_TEXT_LENGTH:
        raise ValueError("canonical decimal exceeds maximum length")
    digits = "".join(str(digit) for digit in significant_digits)
    if exponent >= 0:
        rendered = digits + ("0" * exponent)
    else:
        point = len(digits) + exponent
        if point <= 0:
            rendered = "0." + ("0" * -point) + digits
        else:
            rendered = digits[:point] + "." + digits[point:]
        rendered = rendered.rstrip("0").rstrip(".")
    return f"-{rendered}" if sign else rendered


def parse_decimal(value: object, info: ValidationInfo) -> Decimal:
    """Accept typed Decimal in Python mode and canonical strings in JSON."""
    if info.mode == "python":
        if not isinstance(value, Decimal):
            raise ValueError("Python input must be Decimal")
        parsed = value
    else:
        if not isinstance(value, str):
            raise ValueError("JSON decimal input must be a string")
        if len(value) > MAX_DECIMAL_TEXT_LENGTH:
            raise ValueError("decimal string exceeds maximum length")
        if re.fullmatch(CANONICAL_DECIMAL_PATTERN, value) is None:
            raise ValueError("JSON decimal string is not canonical")
        parsed = Decimal(value)
    rendered = format_decimal(parsed)
    if len(rendered) > MAX_DECIMAL_TEXT_LENGTH:
        raise ValueError("canonical decimal exceeds maximum length")
    return parsed


def require_positive(value: Decimal) -> Decimal:
    if value <= 0:
        raise ValueError("decimal must be positive")
    return value


def require_non_negative(value: Decimal) -> Decimal:
    if value < 0:
        raise ValueError("decimal must be non-negative")
    return value


def _schema(pattern: str, description: str) -> dict[str, object]:
    return {
        "type": "string",
        "pattern": pattern[:-1] + r"(?![\s\S])",
        "maxLength": MAX_DECIMAL_TEXT_LENGTH,
        "description": description,
    }


type CanonicalDecimal = Annotated[
    Decimal,
    BeforeValidator(parse_decimal),
    PlainSerializer(format_decimal, return_type=str, when_used="json"),
    WithJsonSchema(
        _schema(CANONICAL_DECIMAL_PATTERN, "Canonical finite Decimal string"),
        mode="validation",
    ),
    WithJsonSchema(
        _schema(CANONICAL_DECIMAL_PATTERN, "Canonical finite Decimal string"),
        mode="serialization",
    ),
]
type PositiveDecimal = Annotated[
    CanonicalDecimal,
    AfterValidator(require_positive),
    WithJsonSchema(
        _schema(POSITIVE_DECIMAL_PATTERN, "Canonical positive Decimal string"),
        mode="validation",
    ),
    WithJsonSchema(
        _schema(POSITIVE_DECIMAL_PATTERN, "Canonical positive Decimal string"),
        mode="serialization",
    ),
]
type NonNegativeDecimal = Annotated[
    CanonicalDecimal,
    AfterValidator(require_non_negative),
    WithJsonSchema(
        _schema(
            NON_NEGATIVE_DECIMAL_PATTERN,
            "Canonical non-negative Decimal string",
        ),
        mode="validation",
    ),
    WithJsonSchema(
        _schema(
            NON_NEGATIVE_DECIMAL_PATTERN,
            "Canonical non-negative Decimal string",
        ),
        mode="serialization",
    ),
]
```

The displayed contents are authoritative, final, and already Ruff-formatted;
apply them verbatim without semantic or layout edits.

---

Create `src/crypto_lab/domain/records.py` with exactly:

```python
"""Foundational financial and instrument records."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    StringConstraints,
    WithJsonSchema,
    model_validator,
)
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.financial import (
    CanonicalDecimal,
    NonNegativeDecimal,
    PositiveDecimal,
)
from crypto_lab.domain.identifiers import AssetCode

_INSTRUMENT_PATTERN = (
    r"^[A-Z][A-Z0-9]*(?:[._-][A-Z0-9]+)*:"
    r"[A-Z][A-Z0-9]*(?:[._-][A-Z0-9]+)*/"
    r"[A-Z][A-Z0-9]*(?:[._-][A-Z0-9]+)*:"
    r"(?:SPOT|MARGIN|FUTURES|EQUITIES)$"
)
_INSTRUMENT_PARSE_PATTERN = (
    r"^(?P<venue>[A-Z][A-Z0-9]*(?:[._-][A-Z0-9]+)*):"
    r"(?P<base>[A-Z][A-Z0-9]*(?:[._-][A-Z0-9]+)*)/"
    r"(?P<quote>[A-Z][A-Z0-9]*(?:[._-][A-Z0-9]+)*):"
    r"(?P<market>SPOT|MARGIN|FUTURES|EQUITIES)$"
)
_INSTRUMENT_COMPONENT_BOUNDS_PATTERN = (
    r"^[A-Z][A-Z0-9._-]{0,31}:"
    r"[A-Z][A-Z0-9._-]{0,31}/"
    r"[A-Z][A-Z0-9._-]{0,31}:"
    r"(?:SPOT|MARGIN|FUTURES|EQUITIES)$"
)
_INSTRUMENT_SCHEMA_PATTERN = _INSTRUMENT_PATTERN[:-1] + r"(?![\s\S])"
_INSTRUMENT_COMPONENT_BOUNDS_SCHEMA_PATTERN = (
    _INSTRUMENT_COMPONENT_BOUNDS_PATTERN[:-1] + r"(?![\s\S])"
)
_INSTRUMENT_JSON_SCHEMA: JsonSchemaValue = {
    "type": "string",
    "minLength": 10,
    "maxLength": 107,
    "allOf": [
        {"pattern": _INSTRUMENT_SCHEMA_PATTERN},
        {"pattern": _INSTRUMENT_COMPONENT_BOUNDS_SCHEMA_PATTERN},
    ],
}
_INSTRUMENT = re.compile(_INSTRUMENT_PARSE_PATTERN)


def parse_instrument_id(value: str) -> tuple[str, str, str, str]:
    """Parse one complete canonical instrument identity."""
    matched = _INSTRUMENT.fullmatch(value)
    if matched is None:
        raise ValueError("instrument_id is not canonical")
    components = (
        matched["venue"],
        matched["base"],
        matched["quote"],
        matched["market"],
    )
    if any(len(component) > 32 for component in components[:3]):
        raise ValueError("instrument components must not exceed 32 characters")
    return components


def _validate_instrument_id(value: str) -> str:
    parse_instrument_id(value)
    return value


type InstrumentId = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=10,
        max_length=107,
        pattern=_INSTRUMENT_PATTERN,
    ),
    AfterValidator(_validate_instrument_id),
    WithJsonSchema(_INSTRUMENT_JSON_SCHEMA, mode="validation"),
    WithJsonSchema(_INSTRUMENT_JSON_SCHEMA, mode="serialization"),
]


class MarketType(StrEnum):
    """Canonical market vocabulary available for descriptor compatibility."""

    SPOT = "SPOT"
    MARGIN = "MARGIN"
    FUTURES = "FUTURES"
    EQUITIES = "EQUITIES"


class InstrumentRef(CanonicalModel):
    schema_version: Literal["1.0.0"]
    canonical_id: InstrumentId
    venue: AssetCode
    base_asset: AssetCode
    quote_asset: AssetCode
    market_type: MarketType

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if self.base_asset == self.quote_asset:
            raise ValueError("base_asset and quote_asset must differ")
        expected = (
            f"{self.venue}:{self.base_asset}/{self.quote_asset}:"
            f"{self.market_type.value}"
        )
        if self.canonical_id != expected:
            raise ValueError("canonical_id does not match instrument fields")
        return self


class Money(CanonicalModel):
    schema_version: Literal["1.0.0"]
    currency: AssetCode
    amount: CanonicalDecimal


class Price(CanonicalModel):
    schema_version: Literal["1.0.0"]
    instrument_id: InstrumentId
    quote_asset: AssetCode
    value: PositiveDecimal

    @model_validator(mode="after")
    def validate_quote_asset(self) -> Self:
        _, _, quote, _ = parse_instrument_id(self.instrument_id)
        if self.quote_asset != quote:
            raise ValueError("quote_asset does not match instrument_id")
        return self


class Quantity(CanonicalModel):
    schema_version: Literal["1.0.0"]
    instrument_id: InstrumentId
    base_asset: AssetCode
    value: NonNegativeDecimal

    @model_validator(mode="after")
    def validate_base_asset(self) -> Self:
        _, base, _, _ = parse_instrument_id(self.instrument_id)
        if self.base_asset != base:
            raise ValueError("base_asset does not match instrument_id")
        return self
```

Create `src/crypto_lab/domain/versioning.py` with exactly:

```python
"""Stable semantic-version primitive shared across canonical boundaries."""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import AfterValidator, StringConstraints, WithJsonSchema

from crypto_lab.domain.identifiers import exact_string_schema

SEMANTIC_VERSION_PATTERN = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
_SEMANTIC_VERSION = re.compile(SEMANTIC_VERSION_PATTERN)


def parse_semantic_version(value: str) -> tuple[int, int, int]:
    """Return numeric stable semantic-version components."""
    matched = _SEMANTIC_VERSION.fullmatch(value)
    if matched is None:
        raise ValueError("version must be stable canonical MAJOR.MINOR.PATCH")
    major, minor, patch = matched.groups()
    return int(major), int(minor), int(patch)


def _validate_semantic_version(value: str) -> str:
    parse_semantic_version(value)
    return value


type SemanticVersion = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=5,
        max_length=64,
        pattern=SEMANTIC_VERSION_PATTERN,
    ),
    AfterValidator(_validate_semantic_version),
    WithJsonSchema(
        exact_string_schema(
            SEMANTIC_VERSION_PATTERN,
            min_length=5,
            max_length=64,
        )
    ),
]
```

Create `src/crypto_lab/domain/canonical_json.py` with exactly:

```python
"""Deterministic canonical JSON serialization."""

from __future__ import annotations

import json
from datetime import datetime
from decimal import Decimal
from enum import StrEnum

from pydantic import BaseModel

from crypto_lab.domain.financial import format_decimal
from crypto_lab.domain.time import format_utc, require_utc


def _normalize(value: object, active: set[int]) -> object:
    if value is None or type(value) is bool:
        return value
    if isinstance(value, StrEnum):
        return _normalize(value.value, active)
    if type(value) is str or type(value) is int:
        return value
    if isinstance(value, float):
        raise TypeError("float is forbidden in canonical JSON")
    if isinstance(value, Decimal):
        return format_decimal(value)
    if isinstance(value, datetime):
        return format_utc(require_utc(value))
    if isinstance(value, BaseModel):
        identity = id(value)
        if identity in active:
            raise ValueError("cyclic canonical value")
        active.add(identity)
        try:
            dumped = value.model_dump(
                mode="python",
                by_alias=True,
                exclude_none=True,
            )
            return _normalize(dumped, active)
        finally:
            active.remove(identity)
    if type(value) is dict:
        identity = id(value)
        if identity in active:
            raise ValueError("cyclic canonical value")
        active.add(identity)
        try:
            normalized: dict[str, object] = {}
            for key, nested in value.items():
                if type(key) is not str:
                    raise TypeError("canonical JSON object keys must be strings")
                normalized[key] = _normalize(nested, active)
            return normalized
        finally:
            active.remove(identity)
    if type(value) is list or type(value) is tuple:
        identity = id(value)
        if identity in active:
            raise ValueError("cyclic canonical value")
        active.add(identity)
        try:
            return [_normalize(item, active) for item in value]
        finally:
            active.remove(identity)
    raise TypeError(f"unsupported canonical JSON type: {type(value).__name__}")


def canonical_json_text(value: object) -> str:
    """Return canonical compact JSON text."""
    normalized = _normalize(value, set())
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_json_bytes(value: object) -> bytes:
    """Return canonical UTF-8 bytes without a BOM."""
    return canonical_json_text(value).encode("utf-8")
```

Create `src/crypto_lab/domain/hashing.py` with exactly:

```python
"""Named deterministic SHA-256 profiles."""

from __future__ import annotations

from enum import StrEnum
from hashlib import sha256
from typing import Literal, cast

from pydantic import JsonValue

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.identifiers import Sha256

_ATTEMPT_TOKEN_DOMAIN = b"crypto_lab:attempt-token:v1"


class HashingProfile(StrEnum):
    CONFIGURATION_AUDIT_V1 = "configuration-audit/v1"
    CONFIGURATION_MATERIAL_BASE_V1 = "configuration-material-base/v1"
    DATASET_METADATA_V1 = "dataset-metadata/v1"
    ARTIFACT_OWNER_V1 = "artifact-owner/v1"


class CanonicalHashEnvelope(CanonicalModel):
    schema_version: Literal["1.0.0"]
    hashing_profile: HashingProfile
    payload: dict[str, JsonValue]


def sha256_bytes(value: bytes) -> Sha256:
    """Hash exact bytes with SHA-256."""
    return cast(Sha256, sha256(value).hexdigest())


def profile_hash(
    profile: HashingProfile,
    payload: dict[str, JsonValue],
) -> Sha256:
    """Hash one explicit canonical profile envelope."""
    envelope = CanonicalHashEnvelope(
        schema_version="1.0.0",
        hashing_profile=profile,
        payload=payload,
    )
    return sha256_bytes(canonical_json_bytes(envelope))


def attempt_token_hash(token: str) -> Sha256:
    """Hash a raw attempt token with the normative byte domain separator."""
    if type(token) is not str:
        raise TypeError("attempt token must be a built-in string")
    if not token or len(token) > 1024:
        raise ValueError("attempt token length must be 1 through 1024")
    return sha256_bytes(_ATTEMPT_TOKEN_DOMAIN + b"\x00" + token.encode("utf-8"))
```

Create `src/crypto_lab/domain/diagnostics.py` with exactly:

```python
"""Stable bounded machine-readable diagnostics."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, ClassVar, Literal, Self

from pydantic import (
    ConfigDict,
    Field,
    StringConstraints,
    WithJsonSchema,
    field_validator,
    model_validator,
)
from pydantic.experimental.missing_sentinel import MISSING
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.identifiers import (
    DiagnosticId,
    ExperimentId,
    InvocationId,
    NormalizedIdentifier,
    RunId,
    exact_string_schema,
)
from crypto_lab.domain.time import UtcDateTime

_ERROR_CODE_PATTERN = r"^[A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)+$"
_SECRET_KEY_PARTS = {
    "access_token",
    "api_key",
    "attempt_token",
    "auth_token",
    "credential",
    "credentials",
    "password",
    "secret",
    "secrets",
}
_SECRET_KEY_COMPACT = {
    "accesstoken",
    "apikey",
    "attempttoken",
    "authtoken",
    "credential",
    "credentials",
    "password",
    "secret",
    "secrets",
}
MAX_DETAIL_BYTES = 16_384
MAX_DETAIL_DEPTH = 8
MAX_DETAIL_NODES = 256
MAX_DETAIL_COLLECTION = 64
MAX_DETAIL_KEY = 128
MAX_DETAIL_STRING = 2_048
MIN_DETAIL_INTEGER = -(2**63)
MAX_DETAIL_INTEGER = 2**63 - 1

type BoundedDetailInteger = Annotated[
    int,
    Field(
        strict=True,
        ge=MIN_DETAIL_INTEGER,
        le=MAX_DETAIL_INTEGER,
    ),
]
type ErrorCode = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=3,
        max_length=128,
        pattern=_ERROR_CODE_PATTERN,
    ),
    WithJsonSchema(
        exact_string_schema(
            _ERROR_CODE_PATTERN,
            min_length=3,
            max_length=128,
        )
    ),
]
type DiagnosticDetailKey = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=MAX_DETAIL_KEY),
]
type DiagnosticDetailString = Annotated[
    str,
    StringConstraints(strict=True, max_length=MAX_DETAIL_STRING),
]
type DiagnosticDetailValue = (
    DiagnosticDetailString
    | BoundedDetailInteger
    | bool
    | Annotated[list[DiagnosticDetailValue], Field(max_length=MAX_DETAIL_COLLECTION)]
    | Annotated[
        dict[DiagnosticDetailKey, DiagnosticDetailValue],
        Field(max_length=MAX_DETAIL_COLLECTION),
    ]
    | None
)


class DiagnosticSeverity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class DiagnosticCategory(StrEnum):
    USER_CONFIGURATION = "USER_CONFIGURATION"
    SCHEMA_VALIDATION = "SCHEMA_VALIDATION"
    COMPATIBILITY = "COMPATIBILITY"
    ADAPTER_UNAVAILABILITY = "ADAPTER_UNAVAILABILITY"
    ENGINE_RUNTIME = "ENGINE_RUNTIME"
    PROTOCOL = "PROTOCOL"
    TIMEOUT = "TIMEOUT"
    CANCELLATION = "CANCELLATION"
    ARTIFACT_CORRUPTION = "ARTIFACT_CORRUPTION"
    PERSISTENCE = "PERSISTENCE"
    INTERNAL_INVARIANT = "INTERNAL_INVARIANT"
    SECURITY = "SECURITY"


BoundedMessage = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=1024)
]


def _inspect_details(value: DiagnosticDetailValue, depth: int = 0) -> int:
    if depth > MAX_DETAIL_DEPTH:
        raise ValueError("diagnostic details exceed maximum depth")
    if value is None or type(value) is bool:
        return 1
    if type(value) is int:
        if not MIN_DETAIL_INTEGER <= value <= MAX_DETAIL_INTEGER:
            raise ValueError("diagnostic detail integer is outside signed 64-bit range")
        return 1
    if type(value) is str:
        if len(value) > MAX_DETAIL_STRING:
            raise ValueError("diagnostic detail string is too long")
        return 1
    if type(value) is list:
        if len(value) > MAX_DETAIL_COLLECTION:
            raise ValueError("diagnostic detail list is too large")
        return 1 + sum(_inspect_details(item, depth + 1) for item in value)
    if type(value) is dict:
        if len(value) > MAX_DETAIL_COLLECTION:
            raise ValueError("diagnostic detail object is too large")
        nodes = 1
        for key, nested in value.items():
            if len(key) > MAX_DETAIL_KEY:
                raise ValueError("diagnostic detail key is too long")
            separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
            normalized = re.sub(r"[^a-z0-9]+", "_", separated.casefold()).strip("_")
            padded = f"_{normalized}_"
            compact = re.sub(r"[^a-z0-9]+", "", key.casefold())
            if any(
                f"_{secret_key}_" in padded for secret_key in _SECRET_KEY_PARTS
            ) or any(secret_key in compact for secret_key in _SECRET_KEY_COMPACT):
                raise ValueError("secret-like diagnostic detail key is forbidden")
            nodes += _inspect_details(nested, depth + 1)
        return nodes
    raise ValueError("diagnostic details contain an unsupported value")


def _diagnostic_schema_extra(schema: JsonSchemaValue) -> None:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise TypeError("diagnostic schema properties must be an object")
    causal_ids = properties.get("causal_diagnostic_ids")
    if not isinstance(causal_ids, dict):
        raise TypeError("causal diagnostic ID schema must be an object")
    causal_ids["uniqueItems"] = True
    schema["dependentRequired"] = {"run_id": ["experiment_id"]}
    schema["allOf"] = [
        {
            "if": {
                "properties": {
                    "category": {
                        "enum": [
                            "ENGINE_RUNTIME",
                            "PROTOCOL",
                            "TIMEOUT",
                            "CANCELLATION",
                        ]
                    }
                },
                "required": ["category"],
            },
            "then": {"required": ["invocation_id"]},
        }
    ]


def _is_missing(value: object) -> bool:
    return value is MISSING


class Diagnostic(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_diagnostic_schema_extra
    )

    schema_version: Literal["1.0.0"]
    diagnostic_id: DiagnosticId
    severity: DiagnosticSeverity
    error_code: ErrorCode
    category: DiagnosticCategory
    message: BoundedMessage
    source_component: NormalizedIdentifier
    experiment_id: ExperimentId | MISSING = MISSING  # type: ignore[valid-type]
    run_id: RunId | MISSING = MISSING  # type: ignore[valid-type]
    invocation_id: InvocationId | MISSING = MISSING  # type: ignore[valid-type]
    engine: NormalizedIdentifier | MISSING = MISSING  # type: ignore[valid-type]
    retriable: bool
    timestamp_utc: UtcDateTime
    details: Annotated[
        dict[DiagnosticDetailKey, DiagnosticDetailValue],
        Field(max_length=MAX_DETAIL_COLLECTION),
    ]
    causal_diagnostic_ids: tuple[DiagnosticId, ...] = Field(max_length=32)

    @field_validator("details")
    @classmethod
    def validate_details(
        cls,
        value: dict[DiagnosticDetailKey, DiagnosticDetailValue],
    ) -> dict[DiagnosticDetailKey, DiagnosticDetailValue]:
        nodes = _inspect_details(value)
        if nodes > MAX_DETAIL_NODES:
            raise ValueError("diagnostic details contain too many nodes")
        if len(canonical_json_bytes(value)) > MAX_DETAIL_BYTES:
            raise ValueError("diagnostic details exceed maximum encoded bytes")
        return value

    @field_validator("causal_diagnostic_ids")
    @classmethod
    def validate_causal_ids(
        cls,
        value: tuple[DiagnosticId, ...],
    ) -> tuple[DiagnosticId, ...]:
        if len(set(value)) != len(value):
            raise ValueError("causal diagnostic IDs must be unique")
        if value != tuple(sorted(value)):
            raise ValueError("causal diagnostic IDs must be sorted")
        return value

    @model_validator(mode="after")
    def validate_causes(self) -> Self:
        if self.diagnostic_id in self.causal_diagnostic_ids:
            raise ValueError("diagnostic cannot directly cause itself")
        if not _is_missing(self.run_id) and _is_missing(self.experiment_id):
            raise ValueError("run correlation requires experiment correlation")
        command_categories = {
            DiagnosticCategory.ENGINE_RUNTIME,
            DiagnosticCategory.PROTOCOL,
            DiagnosticCategory.TIMEOUT,
            DiagnosticCategory.CANCELLATION,
        }
        if self.category in command_categories and _is_missing(self.invocation_id):
            raise ValueError("command/process/protocol diagnostic requires invocation")
        return self
```

This model is frozen at the field-assignment boundary; its bounded JSON
`details` dictionary is not claimed to be recursively immutable. Services that
retain it must serialize/copy it at their boundary. The secret-like detail-key
check is a defense-in-depth key-name guard only; it does not prove arbitrary
values redacted or secret-free. Stage 5 and Stage 9 retain field-level
redaction, logging, evidence, and audit ownership.

Replace `src/crypto_lab/domain/__init__.py` with exactly:

```python
"""Engine-neutral canonical domain primitives."""

from crypto_lab.domain.base import SCHEMA_VERSION, CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes, canonical_json_text
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticSeverity,
)
from crypto_lab.domain.financial import (
    CanonicalDecimal,
    NonNegativeDecimal,
    PositiveDecimal,
    format_decimal,
)
from crypto_lab.domain.hashing import (
    CanonicalHashEnvelope,
    HashingProfile,
    attempt_token_hash,
    profile_hash,
    sha256_bytes,
)
from crypto_lab.domain.identifiers import (
    ArtifactId,
    AssetCode,
    AuditEventId,
    CandidateArtifactId,
    DatasetId,
    DatasetPartitionId,
    DiagnosticId,
    EventId,
    ExperimentId,
    InvocationId,
    NormalizedIdentifier,
    RunId,
    Sha256,
    StrategyId,
    StrategyVersionId,
)
from crypto_lab.domain.records import (
    InstrumentId,
    InstrumentRef,
    MarketType,
    Money,
    Price,
    Quantity,
)
from crypto_lab.domain.time import UtcDateTime, format_utc
from crypto_lab.domain.versioning import SemanticVersion, parse_semantic_version

__all__ = (
    "SCHEMA_VERSION",
    "ArtifactId",
    "AssetCode",
    "AuditEventId",
    "CandidateArtifactId",
    "CanonicalDecimal",
    "CanonicalHashEnvelope",
    "CanonicalModel",
    "DatasetId",
    "DatasetPartitionId",
    "Diagnostic",
    "DiagnosticCategory",
    "DiagnosticId",
    "DiagnosticSeverity",
    "EventId",
    "ExperimentId",
    "HashingProfile",
    "InstrumentId",
    "InstrumentRef",
    "InvocationId",
    "MarketType",
    "Money",
    "NonNegativeDecimal",
    "NormalizedIdentifier",
    "PositiveDecimal",
    "Price",
    "Quantity",
    "RunId",
    "SemanticVersion",
    "Sha256",
    "StrategyId",
    "StrategyVersionId",
    "UtcDateTime",
    "attempt_token_hash",
    "canonical_json_bytes",
    "canonical_json_text",
    "format_decimal",
    "format_utc",
    "parse_semantic_version",
    "profile_hash",
    "sha256_bytes",
)
```

This is an explicit import-only public surface. It performs no validation or
I/O at import time.

---

### A.2 Configuration files

Create `src/crypto_lab/configuration/models.py` with exactly:

```python
"""Strict Project 1 configuration and typed precedence layers."""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import PureWindowsPath
from typing import Annotated, ClassVar, Literal, Self

from pydantic import (
    AfterValidator,
    ConfigDict,
    Field,
    StringConstraints,
    WithJsonSchema,
    field_validator,
    model_validator,
)
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.identifiers import NormalizedIdentifier, Sha256
from crypto_lab.domain.versioning import SemanticVersion

PathText = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=1024),
]
SafeFilename = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=255,
        pattern=r"^[^<>:\"/\\|?*\x00-\x1f]+$",
    ),
    WithJsonSchema(
        {
            "type": "string",
            "minLength": 1,
            "maxLength": 255,
            "allOf": [
                {"pattern": r"^[^<>:\"/\\|?*\x00-\x1f]+(?![\s\S])"},
                {"not": {"pattern": r"[ .](?![\s\S])"}},
                {
                    "not": {
                        "pattern": (
                            r"^(?:[Aa][Uu][Xx]|[Cc][Oo][Nn]|[Nn][Uu][Ll]|"
                            r"[Pp][Rr][Nn]|[Cc][Oo][Mm][1-9]|[Ll][Pp][Tt][1-9])"
                            r"(?:\..*)?(?![\s\S])"
                        )
                    }
                },
            ],
        }
    ),
]
BoundedText = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=1024),
]


_SECRET_KEY_PARTS = {
    "access_token",
    "api_key",
    "attempt_token",
    "auth_token",
    "credential",
    "credentials",
    "password",
    "secret",
    "secrets",
}
_SECRET_KEY_COMPACT = {
    "accesstoken",
    "apikey",
    "attempttoken",
    "authtoken",
    "credential",
    "credentials",
    "password",
    "secret",
    "secrets",
}
_WINDOWS_RESERVED_NAMES = {
    "AUX",
    "CON",
    "NUL",
    "PRN",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
_MAX_RUNTIME_METADATA_BYTES = 16_384
_MAX_RUNTIME_METADATA_COLLECTION = 64
_MAX_RUNTIME_METADATA_DEPTH = 8
_MAX_RUNTIME_METADATA_KEY = 128
_MAX_RUNTIME_METADATA_NODES = 256
_MAX_RUNTIME_METADATA_STRING = 2_048
_MIN_RUNTIME_METADATA_INTEGER = -(2**63)
_MAX_RUNTIME_METADATA_INTEGER = 2**63 - 1
_INVALID_WINDOWS_PATH_CHARACTERS = re.compile(r'[<>"|?*\x00-\x1f]')
_WINDOWS_RESERVED_SCHEMA_PATTERN = (
    r"(?:^|[\\/])"
    r"(?:[Aa][Uu][Xx]|[Cc][Oo][Nn]|[Nn][Uu][Ll]|[Pp][Rr][Nn]|"
    r"[Cc][Oo][Mm][1-9]|[Ll][Pp][Tt][1-9])"
    r"(?:\.|[\\/]|(?![\s\S]))"
)
MAX_CONFIGURATION_BYTES = 1_048_576
_LOCAL_PATH_JSON_SCHEMA: JsonSchemaValue = {
    "type": "string",
    "minLength": 1,
    "maxLength": 1024,
    "allOf": [
        {
            "pattern": (
                r"^(?:[A-Za-z]:[\\/])?"
                r'[^<>:"/\\|?*\x00-\x1f]+'
                r'(?:[\\/][^<>:"/\\|?*\x00-\x1f]+)*(?![\s\S])'
            )
        },
        {"not": {"pattern": r"(?:^|[\\/])\.{1,2}(?:[\\/]|(?![\s\S]))"}},
        {"not": {"pattern": r"[ .](?:[\\/]|(?![\s\S]))"}},
        {"not": {"pattern": _WINDOWS_RESERVED_SCHEMA_PATTERN}},
    ],
}
_ABSOLUTE_LOCAL_PATH_JSON_SCHEMA: JsonSchemaValue = {
    "type": "string",
    "minLength": 1,
    "maxLength": 1024,
    "allOf": [
        {
            "pattern": (
                r"^[A-Za-z]:[\\/]"
                r'[^<>:"/\\|?*\x00-\x1f]+'
                r'(?:[\\/][^<>:"/\\|?*\x00-\x1f]+)*(?![\s\S])'
            )
        },
        {"not": {"pattern": r"(?:^|[\\/])\.{1,2}(?:[\\/]|(?![\s\S]))"}},
        {"not": {"pattern": r"[ .](?:[\\/]|(?![\s\S]))"}},
        {"not": {"pattern": _WINDOWS_RESERVED_SCHEMA_PATTERN}},
    ],
}


def validate_local_windows_path(
    value: str,
    *,
    require_absolute: bool = False,
) -> str:
    """Validate local Windows path syntax without touching the filesystem."""
    if value.startswith(("\\\\", "//")):
        raise ValueError("path must be local, not UNC")
    if _INVALID_WINDOWS_PATH_CHARACTERS.search(value) is not None:
        raise ValueError("path contains a Windows-invalid character")
    configured = PureWindowsPath(value)
    if configured.drive and not configured.root:
        raise ValueError("drive-relative paths are forbidden")
    if configured.root and not configured.drive:
        raise ValueError("rooted paths require a local drive")
    if require_absolute and not configured.is_absolute():
        raise ValueError("path must be absolute")
    segments = re.split(r"[\\/]", value)
    for index, segment in enumerate(segments):
        is_drive = index == 0 and re.fullmatch(r"[A-Za-z]:", segment) is not None
        trimmed = segment.rstrip(" .")
        stem = trimmed.partition(".")[0].upper()
        if (
            segment in {"", ".", ".."}
            or (":" in segment and not is_drive)
            or trimmed != segment
            or stem in _WINDOWS_RESERVED_NAMES
        ):
            raise ValueError("path contains an unsafe Windows segment")
    return value


def _local_path(value: str) -> str:
    return validate_local_windows_path(value)


def _absolute_local_path(value: str) -> str:
    return validate_local_windows_path(value, require_absolute=True)


LocalPathText = Annotated[
    PathText,
    AfterValidator(_local_path),
    WithJsonSchema(_LOCAL_PATH_JSON_SCHEMA),
]
AbsoluteLocalPathText = Annotated[
    PathText,
    AfterValidator(_absolute_local_path),
    WithJsonSchema(_ABSOLUTE_LOCAL_PATH_JSON_SCHEMA),
]
type BoundedRuntimeMetadataInteger = Annotated[
    int,
    Field(
        strict=True,
        ge=_MIN_RUNTIME_METADATA_INTEGER,
        le=_MAX_RUNTIME_METADATA_INTEGER,
    ),
]
type RuntimeMetadataKey = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=_MAX_RUNTIME_METADATA_KEY,
    ),
]
type RuntimeMetadataString = Annotated[
    str,
    StringConstraints(strict=True, max_length=_MAX_RUNTIME_METADATA_STRING),
]
type RuntimeMetadataValue = (
    RuntimeMetadataString
    | BoundedRuntimeMetadataInteger
    | bool
    | Annotated[
        list[RuntimeMetadataValue],
        Field(max_length=_MAX_RUNTIME_METADATA_COLLECTION),
    ]
    | Annotated[
        dict[RuntimeMetadataKey, RuntimeMetadataValue],
        Field(max_length=_MAX_RUNTIME_METADATA_COLLECTION),
    ]
    | None
)


class RetryTerminalState(StrEnum):
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    UNAVAILABLE = "UNAVAILABLE"


_RETRY_ORDER = tuple(RetryTerminalState)


def _ordered_retry_states(value: object) -> tuple[RetryTerminalState, ...]:
    if not isinstance(value, list | tuple):
        raise ValueError("retry states must be an array")
    if not all(isinstance(item, str | RetryTerminalState) for item in value):
        raise ValueError("retry states must be strings")
    try:
        items = tuple(RetryTerminalState(item) for item in value)
    except ValueError as error:
        raise ValueError("retry states contain a foreign value") from error
    if len(set(items)) != len(items):
        raise ValueError("retry states must be unique")
    return tuple(item for item in _RETRY_ORDER if item in items)


def _set_array_unique(schema: JsonSchemaValue, field: str) -> None:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise TypeError("configuration schema properties must be an object")
    field_schema = properties.get(field)
    if not isinstance(field_schema, dict):
        raise TypeError(f"configuration schema field {field!r} must be an object")
    field_schema["uniqueItems"] = True


def _retry_schema_extra(schema: JsonSchemaValue) -> None:
    _set_array_unique(schema, "automatically_retry_terminal_states")


def _adapters_schema_extra(schema: JsonSchemaValue) -> None:
    _set_array_unique(schema, "entries")


def _inspect_runtime_metadata(value: RuntimeMetadataValue, depth: int = 0) -> int:
    if depth > _MAX_RUNTIME_METADATA_DEPTH:
        raise ValueError("runtime metadata exceeds maximum depth")
    if value is None or type(value) is bool:
        return 1
    if type(value) is int:
        if not _MIN_RUNTIME_METADATA_INTEGER <= value <= _MAX_RUNTIME_METADATA_INTEGER:
            raise ValueError("runtime metadata integer is outside signed 64-bit range")
        return 1
    if type(value) is str:
        if len(value) > _MAX_RUNTIME_METADATA_STRING:
            raise ValueError("runtime metadata string is too long")
        return 1
    if type(value) is dict:
        if len(value) > _MAX_RUNTIME_METADATA_COLLECTION:
            raise ValueError("runtime metadata object is too large")
        nodes = 1
        for key, nested in value.items():
            if len(key) > _MAX_RUNTIME_METADATA_KEY:
                raise ValueError("runtime metadata key is too long")
            separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
            normalized = re.sub(r"[^a-z0-9]+", "_", separated.casefold()).strip("_")
            padded = f"_{normalized}_"
            compact = re.sub(r"[^a-z0-9]+", "", key.casefold())
            if any(
                f"_{secret_key}_" in padded for secret_key in _SECRET_KEY_PARTS
            ) or any(secret_key in compact for secret_key in _SECRET_KEY_COMPACT):
                raise ValueError("secret-like runtime metadata key is forbidden")
            nodes += _inspect_runtime_metadata(nested, depth + 1)
        return nodes
    if type(value) is list:
        if len(value) > _MAX_RUNTIME_METADATA_COLLECTION:
            raise ValueError("runtime metadata list is too large")
        nodes = 1
        for item in value:
            nodes += _inspect_runtime_metadata(item, depth + 1)
        return nodes
    raise ValueError("runtime metadata contains an unsupported value")


class PathsConfig(CanonicalModel):
    runtime_root: LocalPathText = "runtime"
    data_root: LocalPathText = "data"
    artifacts_root: LocalPathText = "artifacts"
    logs_root: LocalPathText = "logs"
    runtimes_root: LocalPathText = "runtimes"


class DatabaseConfig(CanonicalModel):
    filename: SafeFilename = "crypto_lab.sqlite3"
    busy_timeout_ms: int = Field(default=5000, ge=100, le=60000)

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
        trimmed = value.rstrip(" .")
        stem = trimmed.partition(".")[0].upper()
        if value in {".", ".."} or trimmed != value or stem in _WINDOWS_RESERVED_NAMES:
            raise ValueError("database filename is unsafe on Windows")
        return value


class RetryConfig(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_retry_schema_extra
    )

    maximum_attempts_per_slot: int = Field(default=1, ge=1, le=5)
    automatically_retry_terminal_states: tuple[RetryTerminalState, ...] = ()
    retry_delay_seconds: int = Field(default=0, ge=0, le=300)
    require_fresh_availability_observation_for_unavailable: Literal[True] = True

    @field_validator("automatically_retry_terminal_states", mode="before")
    @classmethod
    def normalize_retry_states(
        cls,
        value: object,
    ) -> tuple[RetryTerminalState, ...]:
        return _ordered_retry_states(value)


class SchedulerConfig(CanonicalModel):
    max_concurrent_runs: int = Field(default=1, ge=1, le=8)
    retry: RetryConfig = Field(default_factory=RetryConfig)


class ProcessConfig(CanonicalModel):
    heartbeat_interval_seconds: int = Field(default=15, ge=1, le=300)
    missing_heartbeat_seconds: int = Field(default=45, ge=2, le=900)
    describe_timeout_seconds: int = Field(default=30, ge=1, le=300)
    validate_timeout_seconds: int = Field(default=120, ge=1, le=1800)
    default_run_timeout_seconds: int = Field(default=3600, ge=1, le=604800)
    finalization_timeout_seconds: int = Field(default=300, ge=1, le=3600)
    cancellation_grace_seconds: int = Field(default=10, ge=0, le=300)

    @model_validator(mode="after")
    def validate_heartbeat_ratio(self) -> Self:
        if self.missing_heartbeat_seconds < 2 * self.heartbeat_interval_seconds:
            raise ValueError("missing heartbeat must be at least twice the interval")
        return self


class ProtocolConfig(CanonicalModel):
    max_event_bytes: int = Field(default=1_048_576, ge=4096, le=1_048_576)
    max_manifest_bytes: int = Field(default=16_777_216, ge=65536, le=16_777_216)


class LoggingConfig(CanonicalModel):
    max_stderr_bytes_per_invocation: int = Field(
        default=52_428_800,
        ge=1_048_576,
        le=52_428_800,
    )
    retained_files: int = Field(default=10, ge=1, le=100)


class AdapterEntryConfig(CanonicalModel):
    adapter_name: NormalizedIdentifier
    adapter_version: SemanticVersion
    executable_path: AbsoluteLocalPathText
    executable_hash: Sha256
    runtime_metadata: Annotated[
        dict[RuntimeMetadataKey, RuntimeMetadataValue],
        Field(max_length=_MAX_RUNTIME_METADATA_COLLECTION),
    ] = Field(default_factory=dict)

    @field_validator("runtime_metadata")
    @classmethod
    def validate_runtime_metadata(
        cls,
        value: dict[RuntimeMetadataKey, RuntimeMetadataValue],
    ) -> dict[RuntimeMetadataKey, RuntimeMetadataValue]:
        nodes = _inspect_runtime_metadata(value)
        if nodes > _MAX_RUNTIME_METADATA_NODES:
            raise ValueError("runtime metadata contains too many nodes")
        if len(canonical_json_bytes(value)) > _MAX_RUNTIME_METADATA_BYTES:
            raise ValueError("runtime metadata exceeds maximum encoded bytes")
        return value


class AdaptersConfig(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_adapters_schema_extra
    )

    entries: tuple[AdapterEntryConfig, ...] = Field(default=(), max_length=32)

    @field_validator("entries", mode="before")
    @classmethod
    def normalize_entries(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("entries")
    @classmethod
    def validate_entries(
        cls,
        value: tuple[AdapterEntryConfig, ...],
    ) -> tuple[AdapterEntryConfig, ...]:
        identities = tuple((item.adapter_name, item.adapter_version) for item in value)
        if len(set(identities)) != len(identities):
            raise ValueError("adapter entries must be unique")
        if identities != tuple(sorted(identities)):
            raise ValueError("adapter entries must be deterministically ordered")
        return value


class PolicyConfig(CanonicalModel):
    allow_network: Literal[False] = False
    allow_credentials: Literal[False] = False
    allow_live: Literal[False] = False


class ApplicationConfig(CanonicalModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    paths: PathsConfig = Field(default_factory=PathsConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)
    process: ProcessConfig = Field(default_factory=ProcessConfig)
    protocol: ProtocolConfig = Field(default_factory=ProtocolConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    adapters: AdaptersConfig = Field(default_factory=AdaptersConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)

    @model_validator(mode="after")
    def validate_encoded_size(self) -> Self:
        if len(canonical_json_bytes(self)) > MAX_CONFIGURATION_BYTES:
            raise ValueError("configuration exceeds maximum encoded bytes")
        return self


class PathsLayer(CanonicalModel):
    runtime_root: PathText | None = None
    data_root: PathText | None = None
    artifacts_root: PathText | None = None
    logs_root: PathText | None = None
    runtimes_root: PathText | None = None


class DatabaseLayer(CanonicalModel):
    filename: SafeFilename | None = None
    busy_timeout_ms: int | None = Field(default=None, ge=100, le=60000)


class RetryLayer(CanonicalModel):
    maximum_attempts_per_slot: int | None = Field(default=None, ge=1, le=5)
    automatically_retry_terminal_states: tuple[RetryTerminalState, ...] | None = None
    retry_delay_seconds: int | None = Field(default=None, ge=0, le=300)
    require_fresh_availability_observation_for_unavailable: Literal[True] | None = None

    @field_validator("automatically_retry_terminal_states", mode="before")
    @classmethod
    def normalize_retry_states(cls, value: object) -> object:
        return None if value is None else _ordered_retry_states(value)


class SchedulerLayer(CanonicalModel):
    max_concurrent_runs: int | None = Field(default=None, ge=1, le=8)
    retry: RetryLayer | None = None


class ProcessLayer(CanonicalModel):
    heartbeat_interval_seconds: int | None = Field(default=None, ge=1, le=300)
    missing_heartbeat_seconds: int | None = Field(default=None, ge=2, le=900)
    describe_timeout_seconds: int | None = Field(default=None, ge=1, le=300)
    validate_timeout_seconds: int | None = Field(default=None, ge=1, le=1800)
    default_run_timeout_seconds: int | None = Field(default=None, ge=1, le=604800)
    finalization_timeout_seconds: int | None = Field(default=None, ge=1, le=3600)
    cancellation_grace_seconds: int | None = Field(default=None, ge=0, le=300)


class ProtocolLayer(CanonicalModel):
    max_event_bytes: int | None = Field(default=None, ge=4096, le=1_048_576)
    max_manifest_bytes: int | None = Field(default=None, ge=65536, le=16_777_216)


class LoggingLayer(CanonicalModel):
    max_stderr_bytes_per_invocation: int | None = Field(
        default=None,
        ge=1_048_576,
        le=52_428_800,
    )
    retained_files: int | None = Field(default=None, ge=1, le=100)


class AdaptersLayer(CanonicalModel):
    entries: tuple[AdapterEntryConfig, ...] | None = None

    @field_validator("entries", mode="before")
    @classmethod
    def normalize_entries(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class PolicyLayer(CanonicalModel):
    allow_network: Literal[False] | None = None
    allow_credentials: Literal[False] | None = None
    allow_live: Literal[False] | None = None


class ConfigurationLayer(CanonicalModel):
    schema_version: Literal["1.0.0"]
    paths: PathsLayer | None = None
    database: DatabaseLayer | None = None
    scheduler: SchedulerLayer | None = None
    process: ProcessLayer | None = None
    protocol: ProtocolLayer | None = None
    logging: LoggingLayer | None = None
    adapters: AdaptersLayer | None = None
    policy: PolicyLayer | None = None


class CliOverrides(CanonicalModel):
    runtime_root: PathText | None = None
    data_root: PathText | None = None
    artifacts_root: PathText | None = None
    logs_root: PathText | None = None
    runtimes_root: PathText | None = None
    max_concurrent_runs: int | None = Field(default=None, ge=1, le=8)
    maximum_attempts_per_slot: int | None = Field(default=None, ge=1, le=5)
    automatically_retry_terminal_states: tuple[RetryTerminalState, ...] | None = None
    retry_delay_seconds: int | None = Field(default=None, ge=0, le=300)
    heartbeat_interval_seconds: int | None = Field(default=None, ge=1, le=300)
    missing_heartbeat_seconds: int | None = Field(default=None, ge=2, le=900)
    describe_timeout_seconds: int | None = Field(default=None, ge=1, le=300)
    validate_timeout_seconds: int | None = Field(default=None, ge=1, le=1800)
    default_run_timeout_seconds: int | None = Field(default=None, ge=1, le=604800)
    finalization_timeout_seconds: int | None = Field(default=None, ge=1, le=3600)
    cancellation_grace_seconds: int | None = Field(default=None, ge=0, le=300)

    @field_validator("automatically_retry_terminal_states", mode="before")
    @classmethod
    def normalize_retry_states(cls, value: object) -> object:
        return None if value is None else _ordered_retry_states(value)
```

The displayed contents are final; do not make semantic or layout substitutions.

---

Create `src/crypto_lab/configuration/loader.py` with exactly:

```python
"""Explicit TOML loading and deterministic configuration precedence."""

from __future__ import annotations

import tomllib
from pathlib import Path, PureWindowsPath
from typing import Any, cast

from pydantic import ValidationError

from crypto_lab.configuration.models import (
    MAX_CONFIGURATION_BYTES,
    ApplicationConfig,
    CliOverrides,
    ConfigurationLayer,
    validate_local_windows_path,
)


class ConfigurationError(Exception):
    """Stable code plus caller-supplied path, never source content."""

    def __init__(self, code: str, path: Path | None = None) -> None:
        self.code = code
        self.path = path
        suffix = "" if path is None else f": {path}"
        super().__init__(f"{code}{suffix}")


def _read_layer(path: Path) -> ConfigurationLayer:
    try:
        with path.open("rb") as source:
            encoded = source.read(MAX_CONFIGURATION_BYTES + 1)
        if len(encoded) > MAX_CONFIGURATION_BYTES:
            raise ConfigurationError("CONFIG.LAYER_TOO_LARGE", path)
        text = encoded.decode("utf-8")
        document = tomllib.loads(text)
        return ConfigurationLayer.model_validate(document)
    except ValidationError as error:
        if any("executable_path" in item["loc"] for item in error.errors()):
            raise ConfigurationError(
                "CONFIG.ADAPTER_EXECUTABLE_NOT_ABSOLUTE",
                path,
            ) from error
        raise ConfigurationError("CONFIG.LAYER_INVALID", path) from error
    except (OSError, tomllib.TOMLDecodeError, UnicodeError) as error:
        raise ConfigurationError("CONFIG.LAYER_INVALID", path) from error


def _deep_merge(
    base: dict[str, Any],
    override: dict[str, Any],
) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _deep_merge(current, value)
        else:
            merged[key] = value
    return merged


def _require_absolute_source(path: Path, label: str) -> None:
    rendered = str(path)
    if not path.is_absolute() or rendered.startswith(("\\\\", "//")):
        raise ConfigurationError(f"CONFIG.{label}_PATH_NOT_ABSOLUTE", path)


def _lexical_root(base: Path, value: str) -> str:
    try:
        validate_local_windows_path(value)
    except ValueError as error:
        raise ConfigurationError("CONFIG.UNSAFE_PATH") from error
    configured_windows = PureWindowsPath(value)
    configured = Path(value)
    candidate = configured if configured_windows.is_absolute() else base / configured
    return str(candidate)


def _cli_document(overrides: CliOverrides) -> dict[str, Any]:
    raw = overrides.model_dump(mode="python", exclude_none=True)
    document: dict[str, Any] = {}
    path_names = {
        "runtime_root",
        "data_root",
        "artifacts_root",
        "logs_root",
        "runtimes_root",
    }
    retry_names = {
        "maximum_attempts_per_slot",
        "automatically_retry_terminal_states",
        "retry_delay_seconds",
    }
    process_names = {
        "heartbeat_interval_seconds",
        "missing_heartbeat_seconds",
        "describe_timeout_seconds",
        "validate_timeout_seconds",
        "default_run_timeout_seconds",
        "finalization_timeout_seconds",
        "cancellation_grace_seconds",
    }
    paths = {name: raw[name] for name in path_names if name in raw}
    retry = {name: raw[name] for name in retry_names if name in raw}
    process = {name: raw[name] for name in process_names if name in raw}
    if paths:
        document["paths"] = paths
    scheduler: dict[str, Any] = {}
    if "max_concurrent_runs" in raw:
        scheduler["max_concurrent_runs"] = raw["max_concurrent_runs"]
    if retry:
        scheduler["retry"] = retry
    if scheduler:
        document["scheduler"] = scheduler
    if process:
        document["process"] = process
    return document


def _resolve_paths(config: ApplicationConfig, base: Path) -> ApplicationConfig:
    document = config.model_dump(mode="python")
    paths = cast(dict[str, str], document["paths"])
    document["paths"] = {
        key: _lexical_root(base, value) for key, value in paths.items()
    }
    adapters = cast(dict[str, object], document["adapters"])
    entries = cast(
        list[dict[str, object]] | tuple[dict[str, object], ...],
        adapters["entries"],
    )
    for entry in entries:
        executable = cast(str, entry["executable_path"])
        if not PureWindowsPath(executable).is_absolute():
            raise ConfigurationError("CONFIG.ADAPTER_EXECUTABLE_NOT_ABSOLUTE")
        entry["executable_path"] = _lexical_root(base, executable)
    return ApplicationConfig.model_validate(document)


def load_configuration(
    *,
    primary_path: Path | None,
    local_override_path: Path | None,
    cli_overrides: CliOverrides | None,
    invocation_base: Path,
) -> ApplicationConfig:
    """Load only exact supplied sources under fixed precedence."""
    _require_absolute_source(invocation_base, "INVOCATION_BASE")
    if local_override_path is not None and primary_path is None:
        raise ConfigurationError("CONFIG.OVERRIDE_REQUIRES_PRIMARY")
    base_document = ApplicationConfig().model_dump(mode="python")
    root_base = invocation_base
    if primary_path is not None:
        _require_absolute_source(primary_path, "PRIMARY")
        primary = _read_layer(primary_path)
        base_document = _deep_merge(
            base_document,
            primary.model_dump(mode="python", exclude_none=True),
        )
        root_base = primary_path.parent
    if local_override_path is not None:
        _require_absolute_source(local_override_path, "OVERRIDE")
        local = _read_layer(local_override_path)
        base_document = _deep_merge(
            base_document,
            local.model_dump(mode="python", exclude_none=True),
        )
    if cli_overrides is not None:
        base_document = _deep_merge(base_document, _cli_document(cli_overrides))
    try:
        config = ApplicationConfig.model_validate(base_document)
        return _resolve_paths(config, root_base)
    except ValidationError as error:
        if any("executable_path" in item["loc"] for item in error.errors()):
            raise ConfigurationError(
                "CONFIG.ADAPTER_EXECUTABLE_NOT_ABSOLUTE"
            ) from error
        if any("paths" in item["loc"] for item in error.errors()):
            raise ConfigurationError("CONFIG.UNSAFE_PATH") from error
        raise ConfigurationError("CONFIG.RESOLVED_INVALID") from error
```

Create `src/crypto_lab/configuration/snapshot.py` with exactly:

```python
"""Canonical Stage 3 configuration projections and hashes."""

from __future__ import annotations

from typing import Literal, Self, cast

from pydantic import Field, JsonValue, ValidationError, model_validator

from crypto_lab.configuration.models import (
    MAX_CONFIGURATION_BYTES,
    ApplicationConfig,
)
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_text
from crypto_lab.domain.hashing import HashingProfile, profile_hash
from crypto_lab.domain.identifiers import Sha256


class ConfigSnapshot(CanonicalModel):
    schema_version: Literal["1.0.0"]
    configuration_json: str = Field(
        min_length=2,
        max_length=MAX_CONFIGURATION_BYTES,
    )
    configuration_audit_hash: Sha256
    material_base_configuration_hash: Sha256

    @model_validator(mode="after")
    def validate_canonical_snapshot(self) -> Self:
        if len(self.configuration_json.encode("utf-8")) > MAX_CONFIGURATION_BYTES:
            raise ValueError("configuration snapshot exceeds maximum encoded bytes")
        try:
            config = ApplicationConfig.model_validate_json(self.configuration_json)
        except (ValidationError, ValueError, TypeError):
            raise ValueError("configuration snapshot JSON is invalid") from None
        canonical = canonical_json_text(config)
        if self.configuration_json != canonical:
            raise ValueError("configuration snapshot JSON is not canonical")
        if self.configuration_audit_hash != _configuration_audit_hash(config):
            raise ValueError("configuration snapshot audit hash mismatch")
        if self.material_base_configuration_hash != _material_base_configuration_hash(
            config
        ):
            raise ValueError("configuration snapshot material hash mismatch")
        return self


def _json_payload(value: object) -> dict[str, JsonValue]:
    return cast(dict[str, JsonValue], value)


def _validated_configuration(config: ApplicationConfig) -> ApplicationConfig:
    return ApplicationConfig.model_validate(config.model_dump(mode="python"))


def _configuration_audit_hash(config: ApplicationConfig) -> Sha256:
    return profile_hash(
        HashingProfile.CONFIGURATION_AUDIT_V1,
        _json_payload(config.model_dump(mode="json")),
    )


def _material_base_configuration_hash(config: ApplicationConfig) -> Sha256:
    return profile_hash(
        HashingProfile.CONFIGURATION_MATERIAL_BASE_V1,
        {
            "scheduler": {
                "retry": cast(
                    JsonValue, config.scheduler.retry.model_dump(mode="json")
                ),
            },
            "process": cast(JsonValue, config.process.model_dump(mode="json")),
            "protocol": cast(JsonValue, config.protocol.model_dump(mode="json")),
            "logging": {
                "max_stderr_bytes_per_invocation": (
                    config.logging.max_stderr_bytes_per_invocation
                ),
            },
            "policy": cast(JsonValue, config.policy.model_dump(mode="json")),
        },
    )


def configuration_audit_hash(config: ApplicationConfig) -> Sha256:
    return _configuration_audit_hash(_validated_configuration(config))


def material_base_configuration_hash(config: ApplicationConfig) -> Sha256:
    return _material_base_configuration_hash(_validated_configuration(config))


def snapshot_configuration(config: ApplicationConfig) -> ConfigSnapshot:
    validated = _validated_configuration(config)
    return ConfigSnapshot(
        schema_version="1.0.0",
        configuration_json=canonical_json_text(validated),
        configuration_audit_hash=_configuration_audit_hash(validated),
        material_base_configuration_hash=_material_base_configuration_hash(validated),
    )
```

Replace `src/crypto_lab/configuration/__init__.py` with exactly:

```python
"""Strict explicit configuration boundary for the research core."""

from crypto_lab.configuration.loader import ConfigurationError, load_configuration
from crypto_lab.configuration.models import (
    ApplicationConfig,
    CliOverrides,
    ConfigurationLayer,
    RetryTerminalState,
)
from crypto_lab.configuration.snapshot import (
    ConfigSnapshot,
    configuration_audit_hash,
    material_base_configuration_hash,
    snapshot_configuration,
)

__all__ = (
    "ApplicationConfig",
    "CliOverrides",
    "ConfigSnapshot",
    "ConfigurationError",
    "ConfigurationLayer",
    "RetryTerminalState",
    "configuration_audit_hash",
    "load_configuration",
    "material_base_configuration_hash",
    "snapshot_configuration",
)
```

The displayed contents are final; do not make semantic or layout substitutions.

---

### A.3 Dataset metadata files

Create `src/crypto_lab/datasets/models.py` with exactly:

```python
"""Immutable dataset metadata contracts; no ingestion or file access."""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, ClassVar, Literal, Self

from pydantic import (
    ConfigDict,
    Field,
    StringConstraints,
    WithJsonSchema,
    field_validator,
    model_validator,
)
from pydantic.experimental.missing_sentinel import MISSING
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.identifiers import (
    AssetCode,
    DatasetId,
    DatasetPartitionId,
    DiagnosticId,
    NormalizedIdentifier,
    Sha256,
    exact_string_schema,
)
from crypto_lab.domain.records import InstrumentRef
from crypto_lab.domain.time import UtcDateTime
from crypto_lab.domain.versioning import SemanticVersion

BoundedText = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=1024)
]
Timeframe = Annotated[
    str,
    StringConstraints(
        strict=True, pattern=r"^[1-9][0-9]*(?:s|m|h|d|w)$", max_length=16
    ),
    WithJsonSchema(
        exact_string_schema(
            r"^[1-9][0-9]*(?:s|m|h|d|w)$",
            max_length=16,
        )
    ),
]
_WINDOWS_RESERVED_SEGMENT_PATTERN = (
    r"(?:^|/)(?:[Aa][Uu][Xx]|[Cc][Oo][Nn]|[Nn][Uu][Ll]|[Pp][Rr][Nn]|"
    r"[Cc][Oo][Mm][1-9]|[Ll][Pp][Tt][1-9])"
    r"(?:\.[^/]*)?(?:/|(?![\s\S]))"
)
_REGISTRY_RELATIVE_PATH_SCHEMA: JsonSchemaValue = {
    "type": "string",
    "minLength": 1,
    "maxLength": 1024,
    "allOf": [
        {
            "pattern": (
                r"^[^/<>:\"\\|?*\x00-\x1f]+"
                r"(?:/[^/<>:\"\\|?*\x00-\x1f]+)*(?![\s\S])"
            )
        },
        {"not": {"pattern": r"(?:^|/)\.{1,2}(?:/|(?![\s\S]))"}},
        {"not": {"pattern": r"[ .](?:/|(?![\s\S]))"}},
        {"not": {"pattern": _WINDOWS_RESERVED_SEGMENT_PATTERN}},
    ],
}
RegistryRelativePath = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=1024),
    WithJsonSchema(_REGISTRY_RELATIVE_PATH_SCHEMA),
]


class DatasetDataType(StrEnum):
    OHLCV = "OHLCV"
    TRADES = "TRADES"
    QUOTES = "QUOTES"
    ORDER_BOOK_L2 = "ORDER_BOOK_L2"


class DatasetValidationStatus(StrEnum):
    VALID = "VALID"
    VALID_WITH_WARNINGS = "VALID_WITH_WARNINGS"
    INVALID = "INVALID"


class TimeInterval(CanonicalModel):
    """Half-open interval with inclusive start and exclusive end."""

    start_utc: UtcDateTime
    end_utc: UtcDateTime

    @model_validator(mode="after")
    def validate_bounds(self) -> Self:
        if self.start_utc >= self.end_utc:
            raise ValueError("interval start must precede end")
        return self


class RawSourceProvenance(CanonicalModel):
    source_name: NormalizedIdentifier
    source_version: SemanticVersion
    source_record: BoundedText
    source_hash: Sha256


def _validate_relative_path(value: str) -> str:
    if re.search(r"[<>:\"\\|?*\x00-\x1f]", value) is not None:
        raise ValueError("dataset path contains forbidden syntax")
    segments = value.split("/")
    for segment in segments:
        trimmed = segment.rstrip(" .")
        stem = trimmed.partition(".")[0].upper()
        if (
            segment in {"", ".", ".."}
            or trimmed != segment
            or stem
            in {
                "AUX",
                "CON",
                "NUL",
                "PRN",
                *(f"COM{number}" for number in range(1, 10)),
                *(f"LPT{number}" for number in range(1, 10)),
            }
        ):
            raise ValueError("dataset path contains an unsafe Windows segment")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts:
        raise ValueError("dataset path must be registry-relative")
    if path.as_posix() != value:
        raise ValueError("dataset path must use canonical POSIX syntax")
    return value


def _set_unique_items(schema: JsonSchemaValue, fields: tuple[str, ...]) -> None:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise TypeError("dataset schema properties must be an object")
    for field in fields:
        field_schema = properties.get(field)
        if not isinstance(field_schema, dict):
            raise TypeError(f"dataset schema field {field!r} must be an object")
        field_schema["uniqueItems"] = True


def _partition_schema_extra(schema: JsonSchemaValue) -> None:
    _set_unique_items(schema, ("raw_source_provenance", "quality_observations"))
    schema["allOf"] = [
        {
            "if": {
                "properties": {"row_count": {"const": 0}},
                "required": ["row_count"],
            },
            "then": {"properties": {"quality_observations": {"minItems": 1}}},
        }
    ]


class DatasetPartition(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_partition_schema_extra
    )

    schema_version: Literal["1.0.0"]
    partition_id: DatasetPartitionId
    dataset_id: DatasetId
    ordinal: int = Field(ge=0)
    relative_path: RegistryRelativePath
    content_hash: Sha256
    row_count: int = Field(ge=0)
    start_utc: UtcDateTime
    end_utc: UtcDateTime
    raw_checksum: Sha256
    normalized_checksum: Sha256
    column_schema_version: SemanticVersion
    raw_source_provenance: tuple[RawSourceProvenance, ...] = Field(
        min_length=1,
        max_length=64,
    )
    quality_observations: tuple[BoundedText, ...] = Field(max_length=64)

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        return _validate_relative_path(value)

    @field_validator("quality_observations")
    @classmethod
    def validate_observations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("quality observations must be unique")
        if value != tuple(sorted(value)):
            raise ValueError("quality observations must be sorted")
        return value

    @field_validator("raw_source_provenance")
    @classmethod
    def validate_provenance(
        cls,
        value: tuple[RawSourceProvenance, ...],
    ) -> tuple[RawSourceProvenance, ...]:
        if len(set(value)) != len(value):
            raise ValueError("partition provenance must be unique")
        keys = tuple(
            (
                item.source_name,
                item.source_version,
                item.source_record,
                item.source_hash,
            )
            for item in value
        )
        if keys != tuple(sorted(keys)):
            raise ValueError("partition provenance must be sorted")
        return value

    @model_validator(mode="after")
    def validate_partition(self) -> Self:
        if self.start_utc >= self.end_utc:
            raise ValueError("partition start must precede end")
        if self.row_count == 0 and not self.quality_observations:
            raise ValueError("zero-row partition requires a quality observation")
        return self


class DuplicateInterval(TimeInterval):
    """Half-open interval with at least two observed source rows."""

    duplicate_count: int = Field(ge=2)


def _descriptor_schema_extra(schema: JsonSchemaValue) -> None:
    _set_unique_items(
        schema,
        (
            "raw_source_provenance",
            "partition_ids",
            "missing_intervals",
            "duplicate_intervals",
            "diagnostic_ids",
            "known_limitations",
        ),
    )
    schema["allOf"] = [
        {
            "if": {
                "properties": {"data_type": {"const": "OHLCV"}},
                "required": ["data_type"],
            },
            "then": {"required": ["timeframe"]},
            "else": {"not": {"required": ["timeframe"]}},
        },
        {
            "if": {
                "properties": {"validation_status": {"const": "VALID"}},
                "required": ["validation_status"],
            },
            "then": {
                "properties": {
                    "missing_intervals": {"maxItems": 0},
                    "duplicate_intervals": {"maxItems": 0},
                    "diagnostic_ids": {"maxItems": 0},
                }
            },
        },
        {
            "if": {
                "properties": {"validation_status": {"const": "VALID_WITH_WARNINGS"}},
                "required": ["validation_status"],
            },
            "then": {
                "anyOf": [
                    {"properties": {"missing_intervals": {"minItems": 1}}},
                    {"properties": {"duplicate_intervals": {"minItems": 1}}},
                    {"properties": {"diagnostic_ids": {"minItems": 1}}},
                ]
            },
        },
        {
            "if": {
                "properties": {"validation_status": {"const": "INVALID"}},
                "required": ["validation_status"],
            },
            "then": {"properties": {"diagnostic_ids": {"minItems": 1}}},
        },
    ]


def _is_missing(value: object) -> bool:
    return value is MISSING


class DatasetDescriptor(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_descriptor_schema_extra
    )

    schema_version: Literal["1.0.0"]
    dataset_id: DatasetId
    content_hash: Sha256
    source: BoundedText
    venue: AssetCode
    instrument: InstrumentRef
    data_type: DatasetDataType
    timeframe: Timeframe | MISSING = MISSING  # type: ignore[valid-type]
    start_utc: UtcDateTime
    end_utc: UtcDateTime
    original_timezone: BoundedText
    normalized_to_utc: Literal[True]
    imported_at_utc: UtcDateTime | MISSING = MISSING  # type: ignore[valid-type]
    raw_source_provenance: tuple[RawSourceProvenance, ...] = Field(
        min_length=1, max_length=64
    )
    normalization_implementation: NormalizedIdentifier
    normalization_version: SemanticVersion
    validation_status: DatasetValidationStatus
    partition_ids: tuple[DatasetPartitionId, ...] = Field(min_length=1, max_length=4096)
    missing_intervals: tuple[TimeInterval, ...] = Field(max_length=4096)
    duplicate_intervals: tuple[DuplicateInterval, ...] = Field(max_length=4096)
    diagnostic_ids: tuple[DiagnosticId, ...] = Field(max_length=256)
    raw_checksums: tuple[Sha256, ...] = Field(min_length=1, max_length=4096)
    normalized_checksums: tuple[Sha256, ...] = Field(min_length=1, max_length=4096)
    column_schema_version: SemanticVersion
    known_limitations: tuple[BoundedText, ...] = Field(max_length=64)
    created_at_utc: UtcDateTime

    @field_validator(
        "partition_ids",
        "diagnostic_ids",
        "known_limitations",
    )
    @classmethod
    def validate_unique_tuple(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("dataset collection must contain unique values")
        return value

    @field_validator("missing_intervals")
    @classmethod
    def validate_missing_intervals(
        cls,
        value: tuple[TimeInterval, ...],
    ) -> tuple[TimeInterval, ...]:
        if len(set(value)) != len(value):
            raise ValueError("missing intervals must be unique")
        keys = tuple((item.start_utc, item.end_utc) for item in value)
        if keys != tuple(sorted(keys)):
            raise ValueError("missing intervals must be sorted")
        return value

    @field_validator("duplicate_intervals")
    @classmethod
    def validate_duplicate_intervals(
        cls,
        value: tuple[DuplicateInterval, ...],
    ) -> tuple[DuplicateInterval, ...]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate intervals must be unique")
        keys = tuple(
            (item.start_utc, item.end_utc, item.duplicate_count) for item in value
        )
        if keys != tuple(sorted(keys)):
            raise ValueError("duplicate intervals must be sorted")
        return value

    @field_validator("diagnostic_ids", "known_limitations")
    @classmethod
    def validate_sorted_collections(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(value)):
            raise ValueError("dataset collection must be sorted")
        return value

    @field_validator("raw_source_provenance")
    @classmethod
    def validate_unique_provenance(
        cls,
        value: tuple[RawSourceProvenance, ...],
    ) -> tuple[RawSourceProvenance, ...]:
        if len(set(value)) != len(value):
            raise ValueError("raw source provenance must be unique")
        keys = tuple(
            (
                item.source_name,
                item.source_version,
                item.source_record,
                item.source_hash,
            )
            for item in value
        )
        if keys != tuple(sorted(keys)):
            raise ValueError("raw source provenance must be sorted")
        return value

    @model_validator(mode="after")
    def validate_descriptor(self) -> Self:
        if self.start_utc >= self.end_utc:
            raise ValueError("dataset start must precede end")
        if self.venue != self.instrument.venue:
            raise ValueError("dataset venue must match instrument")
        if self.data_type is DatasetDataType.OHLCV and _is_missing(self.timeframe):
            raise ValueError("OHLCV datasets require a timeframe")
        if self.data_type is not DatasetDataType.OHLCV and not _is_missing(
            self.timeframe
        ):
            raise ValueError("non-OHLCV datasets prohibit a timeframe")
        has_quality_facts = bool(self.missing_intervals or self.duplicate_intervals)
        if self.validation_status is DatasetValidationStatus.VALID:
            if has_quality_facts or self.diagnostic_ids:
                raise ValueError("VALID datasets cannot retain warning/error facts")
        elif self.validation_status is DatasetValidationStatus.VALID_WITH_WARNINGS:
            if not (has_quality_facts or self.diagnostic_ids):
                raise ValueError("warning status requires a quality fact")
        elif not self.diagnostic_ids:
            raise ValueError("INVALID datasets require a diagnostic")
        return self
```

Create `src/crypto_lab/datasets/hashing.py` with exactly:

```python
"""Deterministic in-memory dataset metadata identity."""

from __future__ import annotations

from typing import cast

from pydantic import JsonValue

from crypto_lab.datasets.models import DatasetDescriptor, DatasetPartition
from crypto_lab.domain.hashing import HashingProfile, profile_hash
from crypto_lab.domain.identifiers import Sha256


def _ordered_partitions(
    descriptor: DatasetDescriptor,
    partitions: tuple[DatasetPartition, ...],
) -> tuple[DatasetPartition, ...]:
    by_id = {partition.partition_id: partition for partition in partitions}
    if len(by_id) != len(partitions):
        raise ValueError("partition IDs must be unique")
    if tuple(by_id) != descriptor.partition_ids:
        raise ValueError("partition order must match descriptor partition_ids")
    for expected_ordinal, partition in enumerate(partitions):
        if partition.dataset_id != descriptor.dataset_id:
            raise ValueError("partition belongs to another dataset")
        if partition.ordinal != expected_ordinal:
            raise ValueError("partition ordinal does not match descriptor order")
        if (
            partition.start_utc < descriptor.start_utc
            or partition.end_utc > descriptor.end_utc
        ):
            raise ValueError("partition bounds escape descriptor bounds")
        if any(
            provenance not in descriptor.raw_source_provenance
            for provenance in partition.raw_source_provenance
        ):
            raise ValueError("partition provenance is absent from descriptor")
    if tuple(item.raw_checksum for item in partitions) != descriptor.raw_checksums:
        raise ValueError("raw checksums do not match ordered partitions")
    if (
        tuple(item.normalized_checksum for item in partitions)
        != descriptor.normalized_checksums
    ):
        raise ValueError("normalized checksums do not match ordered partitions")
    if any(
        item.column_schema_version != descriptor.column_schema_version
        for item in partitions
    ):
        raise ValueError("partition column schema version does not match descriptor")
    return partitions


def dataset_metadata_hash(
    descriptor: DatasetDescriptor,
    partitions: tuple[DatasetPartition, ...],
) -> Sha256:
    """Hash material metadata only; never open a partition path."""
    ordered = _ordered_partitions(descriptor, partitions)
    descriptor_payload = descriptor.model_dump(
        mode="json",
        exclude={
            "content_hash",
            "created_at_utc",
            "dataset_id",
            "diagnostic_ids",
            "imported_at_utc",
            "partition_ids",
        },
    )
    partition_payloads = [
        partition.model_dump(
            mode="json",
            exclude={
                "dataset_id",
                "partition_id",
                "relative_path",
            },
        )
        for partition in ordered
    ]
    return profile_hash(
        HashingProfile.DATASET_METADATA_V1,
        {
            "descriptor": cast(JsonValue, descriptor_payload),
            "partitions": cast(
                JsonValue,
                partition_payloads,
            ),
        },
    )


def validate_dataset_identity(
    descriptor: DatasetDescriptor,
    partitions: tuple[DatasetPartition, ...],
) -> None:
    if dataset_metadata_hash(descriptor, partitions) != descriptor.content_hash:
        raise ValueError("dataset content_hash does not match material metadata")
```

Replace `src/crypto_lab/datasets/__init__.py` with exactly:

```python
"""Immutable dataset metadata boundary; Project 1 performs no ingestion."""

from crypto_lab.datasets.hashing import dataset_metadata_hash, validate_dataset_identity
from crypto_lab.datasets.models import (
    DatasetDataType,
    DatasetDescriptor,
    DatasetPartition,
    DatasetValidationStatus,
    DuplicateInterval,
    RawSourceProvenance,
    TimeInterval,
)

__all__ = (
    "DatasetDataType",
    "DatasetDescriptor",
    "DatasetPartition",
    "DatasetValidationStatus",
    "DuplicateInterval",
    "RawSourceProvenance",
    "TimeInterval",
    "dataset_metadata_hash",
    "validate_dataset_identity",
)
```

The displayed contents are final; do not make semantic or layout substitutions.

---

### A.4 Descriptor and artifact-owner files

Create `src/crypto_lab/adapters/versioning.py` with exactly:

```python
"""Pure stable version intersection for later protocol negotiation."""

from __future__ import annotations

from crypto_lab.domain.versioning import SemanticVersion, parse_semantic_version


def highest_common_stable_version(
    core_versions: tuple[SemanticVersion, ...],
    adapter_versions: tuple[SemanticVersion, ...],
) -> SemanticVersion | None:
    """Return the numerically highest exact common stable version."""
    for version in core_versions:
        parse_semantic_version(version)
    for version in adapter_versions:
        parse_semantic_version(version)
    if len(set(core_versions)) != len(core_versions):
        raise ValueError("core versions must be unique")
    if len(set(adapter_versions)) != len(adapter_versions):
        raise ValueError("adapter versions must be unique")
    common = set(core_versions).intersection(adapter_versions)
    if not common:
        return None
    return max(common, key=parse_semantic_version)
```

Create `src/crypto_lab/adapters/descriptors.py` with exactly:

```python
"""Structural engine and adapter descriptors without runtime behavior."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, ClassVar, Literal, Self

from pydantic import (
    ConfigDict,
    Field,
    StringConstraints,
    WithJsonSchema,
    field_validator,
    model_validator,
)
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.identifiers import (
    NormalizedIdentifier,
    Sha256,
    exact_string_schema,
)
from crypto_lab.domain.versioning import SemanticVersion, parse_semantic_version

BoundedText = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=1024)
]
CapabilityName = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=3,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
    ),
    WithJsonSchema(
        exact_string_schema(
            r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
            min_length=3,
            max_length=128,
        )
    ),
]
VocabularyVersion = Annotated[
    str,
    StringConstraints(
        strict=True, pattern=r"^capabilities/v[1-9][0-9]*$", max_length=32
    ),
    WithJsonSchema(
        exact_string_schema(
            r"^capabilities/v[1-9][0-9]*$",
            max_length=32,
        )
    ),
]


class OperatingSystem(StrEnum):
    WINDOWS = "WINDOWS"
    LINUX = "LINUX"
    MACOS = "MACOS"


def _unique_sorted_text(value: tuple[str, ...], label: str) -> tuple[str, ...]:
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must be unique")
    if value != tuple(sorted(value)):
        raise ValueError(f"{label} must be sorted")
    return value


def _unique_sorted_versions(
    value: tuple[SemanticVersion, ...],
    label: str,
) -> tuple[SemanticVersion, ...]:
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must be unique")
    if value != tuple(sorted(value, key=parse_semantic_version)):
        raise ValueError(f"{label} must be numerically sorted")
    return value


def _set_unique_items(schema: JsonSchemaValue, fields: tuple[str, ...]) -> None:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise TypeError("descriptor schema properties must be an object")
    for field in fields:
        field_schema = properties.get(field)
        if not isinstance(field_schema, dict):
            raise TypeError(f"descriptor schema field {field!r} must be an object")
        field_schema["uniqueItems"] = True


def _engine_schema_extra(schema: JsonSchemaValue) -> None:
    _set_unique_items(schema, ("known_limitations",))


def _descriptor_schema_extra(schema: JsonSchemaValue) -> None:
    _set_unique_items(
        schema,
        (
            "supported_protocol_versions",
            "supported_schema_versions",
            "native_capabilities",
            "approximated_capabilities",
            "unsupported_capabilities",
            "supported_operating_systems",
            "runtime_requirements",
            "known_modeling_limitations",
        ),
    )


class EngineDescriptor(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_engine_schema_extra
    )

    schema_version: Literal["1.0.0"]
    engine_name: NormalizedIdentifier
    engine_version: SemanticVersion
    engine_family: NormalizedIdentifier
    planned_role: BoundedText
    known_limitations: tuple[BoundedText, ...] = Field(max_length=64)

    @field_validator("known_limitations")
    @classmethod
    def validate_limitations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted_text(value, "engine limitations")


class SupportedSchemaVersion(CanonicalModel):
    schema_name: NormalizedIdentifier
    schema_version: SemanticVersion


class AdapterDescriptor(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_descriptor_schema_extra
    )

    schema_version: Literal["1.0.0"]
    adapter_name: NormalizedIdentifier
    adapter_version: SemanticVersion
    engine: EngineDescriptor
    supported_protocol_versions: tuple[SemanticVersion, ...] = Field(
        min_length=1, max_length=32
    )
    supported_schema_versions: tuple[SupportedSchemaVersion, ...] = Field(
        min_length=1,
        max_length=128,
    )
    capability_vocabulary_version: VocabularyVersion
    native_capabilities: tuple[CapabilityName, ...] = Field(max_length=256)
    approximated_capabilities: tuple[CapabilityName, ...] = Field(max_length=256)
    unsupported_capabilities: tuple[CapabilityName, ...] = Field(max_length=256)
    supported_operating_systems: tuple[OperatingSystem, ...] = Field(
        min_length=1, max_length=8
    )
    runtime_requirements: tuple[BoundedText, ...] = Field(max_length=64)
    network_required: bool
    credentials_required: bool
    known_modeling_limitations: tuple[BoundedText, ...] = Field(max_length=64)
    executable_hash: Sha256

    @field_validator("supported_protocol_versions")
    @classmethod
    def validate_versions(
        cls,
        value: tuple[SemanticVersion, ...],
    ) -> tuple[SemanticVersion, ...]:
        return _unique_sorted_versions(value, "supported versions")

    @field_validator("supported_schema_versions")
    @classmethod
    def validate_schema_versions(
        cls,
        value: tuple[SupportedSchemaVersion, ...],
    ) -> tuple[SupportedSchemaVersion, ...]:
        keys = tuple(
            (item.schema_name, parse_semantic_version(item.schema_version))
            for item in value
        )
        if len(set(keys)) != len(keys):
            raise ValueError("supported schema versions must be unique")
        if keys != tuple(sorted(keys)):
            raise ValueError("supported schema versions must be sorted")
        return value

    @field_validator(
        "native_capabilities",
        "approximated_capabilities",
        "unsupported_capabilities",
        "runtime_requirements",
        "known_modeling_limitations",
    )
    @classmethod
    def validate_sorted_text(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted_text(value, "descriptor collection")

    @field_validator("supported_operating_systems")
    @classmethod
    def validate_operating_systems(
        cls,
        value: tuple[OperatingSystem, ...],
    ) -> tuple[OperatingSystem, ...]:
        if len(set(value)) != len(value):
            raise ValueError("operating systems must be unique")
        if value != tuple(sorted(value, key=str)):
            raise ValueError("operating systems must be sorted")
        return value

    @model_validator(mode="after")
    def validate_capability_sets(self) -> Self:
        native = set(self.native_capabilities)
        approximated = set(self.approximated_capabilities)
        unsupported = set(self.unsupported_capabilities)
        if native & approximated or native & unsupported or approximated & unsupported:
            raise ValueError("capability declaration sets must be disjoint")
        return self
```

Replace `src/crypto_lab/adapters/__init__.py` with exactly:

```python
"""Structural adapter contracts; no engine or process implementation."""

from crypto_lab.adapters.descriptors import (
    AdapterDescriptor,
    EngineDescriptor,
    OperatingSystem,
    SupportedSchemaVersion,
)
from crypto_lab.adapters.versioning import highest_common_stable_version

__all__ = (
    "AdapterDescriptor",
    "EngineDescriptor",
    "OperatingSystem",
    "SupportedSchemaVersion",
    "highest_common_stable_version",
)
```

Create `src/crypto_lab/artifacts/ownership.py` with exactly:

```python
"""Strict discriminated artifact ownership values."""

from __future__ import annotations

from typing import Annotated, ClassVar, Literal, cast

from pydantic import (
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    TypeAdapter,
    WithJsonSchema,
    model_validator,
)
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.hashing import HashingProfile, profile_hash
from crypto_lab.domain.identifiers import (
    DatasetId,
    ExperimentId,
    InvocationId,
    NormalizedIdentifier,
    RunId,
    Sha256,
    StrategyVersionId,
    exact_string_schema,
)
from crypto_lab.domain.versioning import SemanticVersion

CorrelationId = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
    WithJsonSchema(
        exact_string_schema(
            r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
            min_length=1,
            max_length=128,
        )
    ),
]


class RunArtifactOwner(CanonicalModel):
    owner_kind: Literal["RUN"]
    experiment_id: ExperimentId
    run_id: RunId
    invocation_id: InvocationId | MISSING = MISSING  # type: ignore[valid-type]


class ExperimentArtifactOwner(CanonicalModel):
    owner_kind: Literal["EXPERIMENT"]
    experiment_id: ExperimentId


class DatasetArtifactOwner(CanonicalModel):
    owner_kind: Literal["DATASET"]
    dataset_id: DatasetId


class StrategyArtifactOwner(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "oneOf": [
                {
                    "required": ["strategy_version_id"],
                    "not": {"required": ["strategy_version_hash"]},
                },
                {
                    "required": ["strategy_version_hash"],
                    "not": {"required": ["strategy_version_id"]},
                },
            ]
        }
    )

    owner_kind: Literal["STRATEGY"]
    strategy_version_id: StrategyVersionId | MISSING = MISSING  # type: ignore[valid-type]
    strategy_version_hash: Sha256 | MISSING = MISSING  # type: ignore[valid-type]

    @model_validator(mode="after")
    def validate_strategy_identity(self) -> StrategyArtifactOwner:
        if _is_missing(self.strategy_version_id) == _is_missing(
            self.strategy_version_hash
        ):
            raise ValueError("strategy owner requires exactly one version identity")
        return self


class AdapterArtifactOwner(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "dependentRequired": {
                "engine_name": ["engine_version"],
                "engine_version": ["engine_name"],
            }
        }
    )

    owner_kind: Literal["ADAPTER"]
    adapter_name: NormalizedIdentifier
    adapter_version: SemanticVersion
    engine_name: NormalizedIdentifier | MISSING = MISSING  # type: ignore[valid-type]
    engine_version: SemanticVersion | MISSING = MISSING  # type: ignore[valid-type]

    @model_validator(mode="after")
    def validate_engine_pair(self) -> AdapterArtifactOwner:
        if _is_missing(self.engine_name) != _is_missing(self.engine_version):
            raise ValueError("adapter owner engine name/version must co-occur")
        return self


class SystemArtifactOwner(CanonicalModel):
    owner_kind: Literal["SYSTEM"]
    core_component: NormalizedIdentifier
    correlation_id: CorrelationId


def _is_missing(value: object) -> bool:
    return value is MISSING


type ArtifactOwnerRef = Annotated[
    RunArtifactOwner
    | ExperimentArtifactOwner
    | DatasetArtifactOwner
    | StrategyArtifactOwner
    | AdapterArtifactOwner
    | SystemArtifactOwner,
    Field(discriminator="owner_kind"),
]
ARTIFACT_OWNER_ADAPTER: TypeAdapter[ArtifactOwnerRef] = TypeAdapter(ArtifactOwnerRef)


def owner_presentation(owner: ArtifactOwnerRef) -> dict[str, JsonValue]:
    """Return discriminator-first review presentation, excluding absent fields."""
    raw = cast(dict[str, JsonValue], owner.model_dump(mode="json"))
    kind = raw.pop("owner_kind")
    return {"owner_kind": kind, **raw}


def artifact_owner_hash(owner: ArtifactOwnerRef) -> Sha256:
    """Hash owner presentation through globally sorted canonical JSON."""
    return profile_hash(HashingProfile.ARTIFACT_OWNER_V1, owner_presentation(owner))
```

Replace `src/crypto_lab/artifacts/__init__.py` with exactly:

```python
"""Artifact ownership foundation; finalization remains deferred."""

from crypto_lab.artifacts.ownership import (
    ARTIFACT_OWNER_ADAPTER,
    AdapterArtifactOwner,
    ArtifactOwnerRef,
    DatasetArtifactOwner,
    ExperimentArtifactOwner,
    RunArtifactOwner,
    StrategyArtifactOwner,
    SystemArtifactOwner,
    artifact_owner_hash,
    owner_presentation,
)

__all__ = (
    "ARTIFACT_OWNER_ADAPTER",
    "AdapterArtifactOwner",
    "ArtifactOwnerRef",
    "DatasetArtifactOwner",
    "ExperimentArtifactOwner",
    "RunArtifactOwner",
    "StrategyArtifactOwner",
    "SystemArtifactOwner",
    "artifact_owner_hash",
    "owner_presentation",
)
```

The displayed contents are final; do not make semantic or layout substitutions.

---

### A.5 Schema registry and schema tooling

Create `src/crypto_lab/schema_registry.py` with exactly:

```python
"""Closed deterministic registry for the Stage 3 JSON Schemas."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from pydantic import TypeAdapter

from crypto_lab.adapters.descriptors import AdapterDescriptor, EngineDescriptor
from crypto_lab.artifacts.ownership import ARTIFACT_OWNER_ADAPTER
from crypto_lab.configuration.models import ApplicationConfig
from crypto_lab.datasets.models import DatasetDescriptor, DatasetPartition
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.records import InstrumentRef, Money, Price, Quantity

JSON_SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"


@dataclass(frozen=True, slots=True)
class SchemaDefinition:
    relative_path: PurePosixPath
    schema_id: str
    adapter: TypeAdapter[Any]


SCHEMA_DEFINITIONS: tuple[SchemaDefinition, ...] = (
    SchemaDefinition(
        PurePosixPath("domain/instrument-ref-v1.schema.json"),
        "urn:crypto-lab:schema:domain:instrument-ref:1.0.0",
        TypeAdapter(InstrumentRef),
    ),
    SchemaDefinition(
        PurePosixPath("domain/money-v1.schema.json"),
        "urn:crypto-lab:schema:domain:money:1.0.0",
        TypeAdapter(Money),
    ),
    SchemaDefinition(
        PurePosixPath("domain/price-v1.schema.json"),
        "urn:crypto-lab:schema:domain:price:1.0.0",
        TypeAdapter(Price),
    ),
    SchemaDefinition(
        PurePosixPath("domain/quantity-v1.schema.json"),
        "urn:crypto-lab:schema:domain:quantity:1.0.0",
        TypeAdapter(Quantity),
    ),
    SchemaDefinition(
        PurePosixPath("domain/diagnostic-v1.schema.json"),
        "urn:crypto-lab:schema:domain:diagnostic:1.0.0",
        TypeAdapter(Diagnostic),
    ),
    SchemaDefinition(
        PurePosixPath("configuration/application-config-v1.schema.json"),
        "urn:crypto-lab:schema:configuration:application-config:1.0.0",
        TypeAdapter(ApplicationConfig),
    ),
    SchemaDefinition(
        PurePosixPath("datasets/dataset-partition-v1.schema.json"),
        "urn:crypto-lab:schema:datasets:dataset-partition:1.0.0",
        TypeAdapter(DatasetPartition),
    ),
    SchemaDefinition(
        PurePosixPath("datasets/dataset-descriptor-v1.schema.json"),
        "urn:crypto-lab:schema:datasets:dataset-descriptor:1.0.0",
        TypeAdapter(DatasetDescriptor),
    ),
    SchemaDefinition(
        PurePosixPath("protocol/engine-descriptor-v1.schema.json"),
        "urn:crypto-lab:schema:protocol:engine-descriptor:1.0.0",
        TypeAdapter(EngineDescriptor),
    ),
    SchemaDefinition(
        PurePosixPath("protocol/adapter-descriptor-v1.schema.json"),
        "urn:crypto-lab:schema:protocol:adapter-descriptor:1.0.0",
        TypeAdapter(AdapterDescriptor),
    ),
    SchemaDefinition(
        PurePosixPath("artifacts/artifact-owner-ref-v1.schema.json"),
        "urn:crypto-lab:schema:artifacts:artifact-owner-ref:1.0.0",
        ARTIFACT_OWNER_ADAPTER,
    ),
)


def render_schema_files() -> dict[PurePosixPath, bytes]:
    """Render the closed schema registry as canonical UTF-8 plus one LF."""
    paths = tuple(item.relative_path for item in SCHEMA_DEFINITIONS)
    identifiers = tuple(item.schema_id for item in SCHEMA_DEFINITIONS)
    if len(set(paths)) != len(paths) or len(set(identifiers)) != len(identifiers):
        raise RuntimeError("schema registry paths and IDs must be unique")
    rendered: dict[PurePosixPath, bytes] = {}
    for definition in SCHEMA_DEFINITIONS:
        schema = definition.adapter.json_schema(mode="serialization")
        schema["$schema"] = JSON_SCHEMA_DRAFT
        schema["$id"] = definition.schema_id
        rendered[definition.relative_path] = canonical_json_bytes(schema) + b"\n"
    return rendered
```

Create `scripts/generate_schemas.py` with exactly:

```python
"""Write or check the closed Stage 3 schema registry."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

from crypto_lab.schema_registry import render_schema_files


def _schema_files(root: Path) -> set[PurePosixPath]:
    if root.is_symlink():
        raise ValueError(f"schema output root must not be a symlink: {root}")
    if not root.exists():
        return set()
    files: set[PurePosixPath] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"schema output entry must not be a symlink: {path}")
        if path.is_file():
            files.add(PurePosixPath(path.relative_to(root).as_posix()))
    return files


def _write(output: Path, expected: dict[PurePosixPath, bytes]) -> int:
    output.mkdir(parents=True, exist_ok=True)
    unexpected = _schema_files(output) - set(expected)
    if unexpected:
        for relative_path in sorted(unexpected):
            print(
                f"unexpected schema output file: {relative_path.as_posix()}",
                file=sys.stderr,
            )
        return 1
    for relative_path in sorted(expected):
        contents = expected[relative_path]
        target = output.joinpath(*relative_path.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(contents)
    return 0


def _check(output: Path, expected: dict[PurePosixPath, bytes]) -> int:
    actual_paths = _schema_files(output)
    expected_paths = set(expected)
    failures: list[str] = []
    for relative_path in sorted(expected_paths - actual_paths):
        failures.append(f"missing schema: {relative_path.as_posix()}")
    for relative_path in sorted(actual_paths - expected_paths):
        failures.append(f"unexpected schema: {relative_path.as_posix()}")
    for relative_path in sorted(expected_paths & actual_paths):
        target = output.joinpath(*relative_path.parts)
        if target.read_bytes() != expected[relative_path]:
            failures.append(f"changed schema: {relative_path.as_posix()}")
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    expected = render_schema_files()
    try:
        if args.write:
            return _write(args.output, expected)
        return _check(args.output, expected)
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

Create `scripts/verify_schema_distribution.py` with exactly:

```python
"""Verify exact schema bytes and locations in the wheel and sdist."""

from __future__ import annotations

import argparse
import sys
import tarfile
import zipfile
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

from crypto_lab.schema_registry import render_schema_files


def _single(paths: list[Path], label: str) -> Path:
    if len(paths) != 1:
        raise ValueError(f"expected exactly one {label}; found {len(paths)}")
    return paths[0]


def _verify_source(source: Path, expected: dict[PurePosixPath, bytes]) -> None:
    if source.is_symlink():
        raise ValueError(f"source schema root must not be a symlink: {source}")
    actual: dict[PurePosixPath, bytes] = {}
    for path in source.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"source schema entry must not be a symlink: {path}")
        if path.is_file():
            relative = PurePosixPath(path.relative_to(source).as_posix())
            actual[relative] = path.read_bytes()
    if actual != expected:
        raise ValueError("source schema tree does not match the closed registry")


def _verify_wheel(wheel: Path, expected: dict[PurePosixPath, bytes]) -> None:
    with zipfile.ZipFile(wheel) as archive:
        entries = archive.infolist()
        if any("\\" in entry.filename for entry in entries):
            raise ValueError("wheel entries must use POSIX separators")
        expected_names = {
            f"crypto_lab/schemas/{relative_path.as_posix()}"
            for relative_path in expected
        }
        expected_directories = {"crypto_lab", "crypto_lab/schemas"}
        for name in expected_names:
            parts = name.split("/")[:-1]
            expected_directories.update(
                "/".join(parts[:index]) for index in range(1, len(parts) + 1)
            )
        relevant = [
            entry
            for entry in entries
            if entry.filename.rstrip("/") in {"crypto_lab", "crypto_lab/schemas"}
            or entry.filename.startswith("crypto_lab/schemas/")
            or entry.filename.endswith(".schema.json")
        ]
        names: list[str] = []
        by_name: dict[str, zipfile.ZipInfo] = {}
        for entry in relevant:
            normalized = entry.filename.rstrip("/")
            mode = (entry.external_attr >> 16) & 0o170000
            if normalized in expected_directories:
                if not entry.is_dir() or mode not in {0, 0o040000}:
                    raise ValueError("wheel schema root entries must be directories")
                continue
            if normalized not in expected_names:
                raise ValueError(f"unexpected wheel schema entry: {entry.filename}")
            if entry.is_dir() or mode not in {0, 0o100000}:
                raise ValueError("wheel schema payloads must be regular files")
            names.append(normalized)
            by_name[normalized] = entry
        if len(names) != len(expected_names) or set(names) != expected_names:
            raise ValueError(
                "wheel schema entries are missing, duplicated, or unexpected"
            )
        for relative_path, contents in expected.items():
            name = f"crypto_lab/schemas/{relative_path.as_posix()}"
            if by_name[name].file_size != len(contents):
                raise ValueError(f"wheel schema size differs: {name}")
            if archive.read(name) != contents:
                raise ValueError(f"wheel schema bytes differ: {name}")


def _verify_sdist(sdist: Path, expected: dict[PurePosixPath, bytes]) -> None:
    with tarfile.open(sdist, mode="r:gz") as archive:
        archive_root = sdist.name.removesuffix(".tar.gz")
        schema_prefix = f"{archive_root}/schemas/"
        all_members = archive.getmembers()
        if any("\\" in member.name for member in all_members):
            raise ValueError("sdist entries must use POSIX separators")
        expected_names = {
            f"{archive_root}/schemas/{relative_path.as_posix()}"
            for relative_path in expected
        }
        expected_directories = {archive_root, f"{archive_root}/schemas"}
        for name in expected_names:
            parts = name.split("/")[:-1]
            expected_directories.update(
                "/".join(parts[:index]) for index in range(1, len(parts) + 1)
            )
        relevant = [
            member
            for member in all_members
            if member.name.rstrip("/") in {archive_root, f"{archive_root}/schemas"}
            or member.name.startswith(schema_prefix)
            or member.name.endswith(".schema.json")
        ]
        names: list[str] = []
        members_by_name: dict[str, tarfile.TarInfo] = {}
        for member in relevant:
            normalized = member.name.rstrip("/")
            if normalized in expected_directories:
                if not member.isdir():
                    raise ValueError("sdist schema root entries must be directories")
                continue
            if normalized not in expected_names:
                raise ValueError(f"unexpected sdist schema entry: {member.name}")
            if not member.isfile():
                raise ValueError("sdist schema payloads must be regular files")
            names.append(normalized)
            members_by_name[normalized] = member
        if len(names) != len(expected_names) or set(names) != expected_names:
            raise ValueError(
                "sdist schema entries are missing, duplicated, or unexpected"
            )
        for relative_path, contents in expected.items():
            name = f"{archive_root}/schemas/{relative_path.as_posix()}"
            member = members_by_name[name]
            if member.size != len(contents):
                raise ValueError(f"sdist schema size differs: {name}")
            extracted = archive.extractfile(member)
            if extracted is None or extracted.read() != contents:
                raise ValueError(f"sdist schema bytes differ: {name}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--dist", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    expected = render_schema_files()
    try:
        _verify_source(args.source, expected)
        wheel = _single(sorted(args.dist.glob("*.whl")), "wheel")
        sdist = _single(sorted(args.dist.glob("*.tar.gz")), "sdist")
        _verify_wheel(wheel, expected)
        _verify_sdist(sdist, expected)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Neither script performs I/O merely by being imported. The 11 generated schema
files are the byte-for-byte output of the displayed registry and generator;
their exact contents are therefore supplied by this deterministic generation
command rather than duplicated in the plan:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 schema-generate-write
```

Run the same command with `--check` immediately afterward and review all 11
generated files before staging them. The generator never discovers model types
or output roots implicitly.

---

### A.6 Project metadata and complete verifier

Apply this exact cumulative patch to `pyproject.toml` across Tasks 1, 7, and 8:

```diff
@@
-dependencies = []
+dependencies = [
+  "pydantic>=2.12,<3",
+]
@@
 dev = [
   "hatchling>=1.27,<2",
+  "hypothesis>=6.130,<7",
+  "jsonschema>=4.23,<5",
   "mypy>=1.15,<2",
@@
 [tool.hatch.build.targets.wheel]
 packages = ["src/crypto_lab"]
 dev-mode-dirs = ["src"]
+
+[tool.hatch.build.targets.wheel.force-include]
+"schemas" = "crypto_lab/schemas"
@@
   "/scripts",
+  "/schemas",
   "/docs/development",
@@
-src = ["src", "tests"]
+src = ["src", "tests", "scripts"]
 extend-exclude = [
   "docs/superpowers/plans/2026-08-10-project-1-foundation-implementation-plan.md",
+  "docs/superpowers/plans/2026-08-10-project-1-canonical-domain-configuration-hashing-schemas-implementation-plan.md",
 ]
@@
-files = ["src", "tests"]
+files = ["src", "tests", "scripts"]
```

The wheel force-include has exactly one source key and one package destination.
Do not add a root-level wheel copy, broad Markdown exclusion, alternate package
source, or optional dependency group. `uv.lock` is regenerated only by the
Task 1 commands and is never hand-edited.

Create `scripts/invoke-uv.ps1` in Task 1 with exactly:

```powershell
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($args.Count -eq 0) {
    throw "An invoke-uv operation is required"
}

$repositoryRoot = (
    Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath "..")
).Path
$operation = [string]$args[0]
[object[]]$tail = @(
    if ($args.Count -gt 1) {
        $args[1..($args.Count - 1)]
    }
)

function Resolve-ClosedRepositoryPath {
    param(
        [string]$Candidate,
        [bool]$AllowDirectory
    )

    $fullPath = [System.IO.Path]::GetFullPath($Candidate)
    $normalizedRoot = $repositoryRoot.TrimEnd("\")
    $rootPrefix = "$normalizedRoot\"
    if (
        -not $fullPath.StartsWith(
            $rootPrefix,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw "Path must remain below the repository root: $Candidate"
    }
    $relativePath = $fullPath.Substring($rootPrefix.Length)
    $segments = $relativePath.Split("\")
    if ($segments.Count -eq 0 -or $segments -contains "") {
        throw "Path must identify a normalized repository entry: $Candidate"
    }
    $currentPath = $normalizedRoot
    $rootItem = Get-Item -LiteralPath $currentPath -Force
    if (
        ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) `
        -ne 0
    ) {
        throw "Repository root must not be a reparse point"
    }
    foreach ($segment in $segments) {
        $currentPath = Join-Path -Path $currentPath -ChildPath $segment
        $item = Get-Item -LiteralPath $currentPath -Force
        if (
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) `
            -ne 0
        ) {
            throw "Repository path must not traverse a reparse point: $Candidate"
        }
    }
    if (-not $AllowDirectory -and $item.PSIsContainer) {
        throw "Expected a regular file: $Candidate"
    }
    return $fullPath
}

function Resolve-ClosedSchemaWriteDirectory {
    $normalizedRoot = $repositoryRoot.TrimEnd("\")
    $candidate = [System.IO.Path]::GetFullPath(
        (Join-Path $normalizedRoot "schemas")
    )
    $parent = [System.IO.Path]::GetDirectoryName($candidate)
    if (
        $parent -cne $normalizedRoot `
        -or [System.IO.Path]::GetFileName($candidate) -cne "schemas"
    ) {
        throw "Schema write path must be the exact repository schemas directory"
    }
    $rootItem = Get-Item -LiteralPath $normalizedRoot -Force
    if (
        ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) `
        -ne 0
    ) {
        throw "Repository root must not be a reparse point"
    }
    if ([System.IO.File]::Exists($candidate)) {
        throw "Schema write path must not be a file"
    }
    if ([System.IO.Directory]::Exists($candidate)) {
        $schemaItem = Get-Item -LiteralPath $candidate -Force
        if (
            ($schemaItem.Attributes -band `
                [System.IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw "Schema write path must not be a reparse point"
        }
    }
    return $candidate
}

$pythonExecutable = Resolve-ClosedRepositoryPath `
    (Join-Path $repositoryRoot ".venv\Scripts\python.exe") $false
$coverageConfig = Resolve-ClosedRepositoryPath `
    (Join-Path $repositoryRoot "pyproject.toml") $false
$uvBaseArguments = @(
    "--directory",
    $repositoryRoot,
    "--project",
    $repositoryRoot,
    "--no-config",
    "--managed-python",
    "--no-python-downloads"
)
$runPrefix = $uvBaseArguments + @(
    "--offline",
    "run",
    "--no-sync",
    "--no-env-file",
    "--python",
    $pythonExecutable,
    "--"
)
$pytestPrefix = @(
    $pythonExecutable,
    "-I",
    "-B",
    "-m",
    "pytest",
    "--disable-plugin-autoload",
    "-p",
    "pytest_cov.plugin",
    "--cov-config=$coverageConfig"
)

switch -CaseSensitive ($operation) {
    "lock-check" {
        if ($tail.Count -ne 0) {
            throw "lock-check accepts no arguments"
        }
        $uvArguments = $uvBaseArguments + @(
            "--offline",
            "lock",
            "--check",
            "--python",
            $pythonExecutable
        )
    }
    "lock-resolve-offline" {
        if ($tail.Count -ne 0) {
            throw "lock-resolve-offline accepts no arguments"
        }
        $uvArguments = $uvBaseArguments + @(
            "--offline",
            "lock",
            "--python",
            $pythonExecutable
        )
    }
    "sync" {
        if ($tail.Count -ne 0) {
            throw "sync accepts no arguments"
        }
        $uvArguments = $uvBaseArguments + @(
            "--offline",
            "sync",
            "--frozen",
            "--no-build-isolation",
            "--python",
            $pythonExecutable
        )
    }
    "lock-acquire" {
        if ($tail.Count -ne 0) {
            throw "lock-acquire accepts no arguments"
        }
        $uvArguments = $uvBaseArguments + @(
            "lock",
            "--python",
            $pythonExecutable
        )
    }
    "sync-acquire" {
        if ($tail.Count -ne 0) {
            throw "sync-acquire accepts no arguments"
        }
        $uvArguments = $uvBaseArguments + @(
            "sync",
            "--frozen",
            "--no-install-project",
            "--no-build-isolation",
            "--python",
            $pythonExecutable
        )
    }
    "ruff-format-all" {
        if ($tail.Count -ne 0) {
            throw "ruff-format-all accepts no arguments"
        }
        $ruffExecutable = Resolve-ClosedRepositoryPath `
            (Join-Path $repositoryRoot ".venv\Scripts\ruff.exe") $false
        $uvArguments = $runPrefix + @(
            $ruffExecutable,
            "format",
            "--check",
            "."
        )
    }
    "ruff-check-all" {
        if ($tail.Count -ne 0) {
            throw "ruff-check-all accepts no arguments"
        }
        $ruffExecutable = Resolve-ClosedRepositoryPath `
            (Join-Path $repositoryRoot ".venv\Scripts\ruff.exe") $false
        $uvArguments = $runPrefix + @($ruffExecutable, "check", ".")
    }
    "mypy-all" {
        if ($tail.Count -ne 0) {
            throw "mypy-all accepts no arguments"
        }
        $uvArguments = $runPrefix + @(
            $pythonExecutable,
            "-I",
            "-B",
            "-m",
            "mypy"
        )
    }
    "pytest-all" {
        if ($tail.Count -ne 0) {
            throw "pytest-all accepts no arguments"
        }
        $uvArguments = $runPrefix + $pytestPrefix
    }
    "pytest-launcher-bootstrap" {
        if ($tail.Count -ne 0) {
            throw "pytest-launcher-bootstrap accepts no arguments"
        }
        $launcherTest = Resolve-ClosedRepositoryPath `
            (Join-Path $repositoryRoot "tests\safety\test_uv_launcher.py") `
            $false
        $uvArguments = $runPrefix + $pytestPrefix + @(
            "-o",
            "addopts=",
            $launcherTest,
            "-k",
            "launcher and not validation_libraries and not pydantic",
            "-q"
        )
    }
    "pytest-focused" {
        if ($tail.Count -eq 0) {
            throw "pytest-focused requires at least one test target"
        }
        $pytestArguments = [System.Collections.Generic.List[object]]::new()
        $index = 0
        if (
            $tail.Count -ge 2 `
            -and [string]$tail[0] -ceq "-o" `
            -and [string]$tail[1] -ceq "addopts="
        ) {
            [void]$pytestArguments.Add("-o")
            [void]$pytestArguments.Add("addopts=")
            $index = 2
        }
        $targetCount = 0
        while ($index -lt $tail.Count) {
            $argument = [string]$tail[$index]
            if ($argument -ceq "-q" -and $index -eq $tail.Count - 1) {
                [void]$pytestArguments.Add($argument)
                $index += 1
                continue
            }
            if ($argument.StartsWith("-", [System.StringComparison]::Ordinal)) {
                throw "pytest-focused accepts only test targets and final -q"
            }
            $normalized = $argument.Replace("\", "/")
            if (
                $normalized -cnotmatch `
                    '^tests/[A-Za-z0-9_./-]+(?:::[A-Za-z0-9_]+)?$'
            ) {
                throw "pytest-focused target contains unsupported characters"
            }
            $targetParts = $normalized -split "::", 2
            $targetPath = $targetParts[0]
            if (
                [System.IO.Path]::IsPathRooted($targetPath) `
                -or -not $targetPath.StartsWith(
                    "tests/",
                    [System.StringComparison]::Ordinal
                ) `
                -or $targetPath.Contains(":")
            ) {
                throw "pytest-focused target must be repository-relative under tests/"
            }
            $segments = $targetPath.Split("/")
            if (
                $segments -contains "" `
                -or $segments -contains "." `
                -or $segments -contains ".."
            ) {
                throw "pytest-focused target is not normalized"
            }
            $resolvedTarget = Resolve-ClosedRepositoryPath `
                (Join-Path $repositoryRoot $targetPath.Replace("/", "\")) `
                $true
            $nodeSuffix = if ($targetParts.Count -eq 2) {
                "::$($targetParts[1])"
            }
            else {
                ""
            }
            [void]$pytestArguments.Add("$resolvedTarget$nodeSuffix")
            $targetCount += 1
            $index += 1
        }
        if ($targetCount -eq 0) {
            throw "pytest-focused requires at least one test target"
        }
        $uvArguments = $runPrefix + $pytestPrefix + @($pytestArguments)
    }
    "schema-generate-write" {
        if ($tail.Count -ne 0) {
            throw "schema-generate-write accepts no arguments"
        }
        $schemaGenerator = Resolve-ClosedRepositoryPath `
            (Join-Path $repositoryRoot "scripts\generate_schemas.py") $false
        $schemaDirectory = Resolve-ClosedSchemaWriteDirectory
        $uvArguments = $runPrefix + @(
            $pythonExecutable,
            "-I",
            "-B",
            $schemaGenerator,
            "--output",
            $schemaDirectory,
            "--write"
        )
    }
    "schema-generate-check" {
        if ($tail.Count -ne 0) {
            throw "schema-generate-check accepts no arguments"
        }
        $schemaGenerator = Resolve-ClosedRepositoryPath `
            (Join-Path $repositoryRoot "scripts\generate_schemas.py") $false
        $schemaDirectory = Resolve-ClosedRepositoryPath `
            (Join-Path $repositoryRoot "schemas") $true
        $uvArguments = $runPrefix + @(
            $pythonExecutable,
            "-I",
            "-B",
            $schemaGenerator,
            "--output",
            $schemaDirectory,
            "--check"
        )
    }
    "schema-distribution" {
        if ($tail.Count -ne 0) {
            throw "schema-distribution accepts no arguments"
        }
        $schemaVerifier = Resolve-ClosedRepositoryPath `
            (Join-Path $repositoryRoot `
                "scripts\verify_schema_distribution.py") $false
        $schemaDirectory = Resolve-ClosedRepositoryPath `
            (Join-Path $repositoryRoot "schemas") $true
        $distDirectory = Resolve-ClosedRepositoryPath `
            (Join-Path $repositoryRoot "dist") $true
        $uvArguments = $runPrefix + @(
            $pythonExecutable,
            "-I",
            "-B",
            $schemaVerifier,
            "--source",
            $schemaDirectory,
            "--dist",
            $distDirectory
        )
    }
    "cli-version" {
        if ($tail.Count -ne 0) {
            throw "cli-version accepts no arguments"
        }
        $cliExecutable = Resolve-ClosedRepositoryPath `
            (Join-Path $repositoryRoot ".venv\Scripts\crypto-lab.exe") $false
        $uvArguments = $runPrefix + @($cliExecutable, "--version")
    }
    "cli-module-version" {
        if ($tail.Count -ne 0) {
            throw "cli-module-version accepts no arguments"
        }
        $uvArguments = $runPrefix + @(
            $pythonExecutable,
            "-I",
            "-B",
            "-m",
            "crypto_lab.cli",
            "--version"
        )
    }
    "cli-help" {
        if ($tail.Count -ne 0) {
            throw "cli-help accepts no arguments"
        }
        $cliExecutable = Resolve-ClosedRepositoryPath `
            (Join-Path $repositoryRoot ".venv\Scripts\crypto-lab.exe") $false
        $uvArguments = $runPrefix + @($cliExecutable)
    }
    "cli-unknown" {
        if ($tail.Count -ne 0) {
            throw "cli-unknown accepts no arguments"
        }
        $cliExecutable = Resolve-ClosedRepositoryPath `
            (Join-Path $repositoryRoot ".venv\Scripts\crypto-lab.exe") $false
        $uvArguments = $runPrefix + @($cliExecutable, "--unknown")
    }
    "pydantic-proof" {
        if ($tail.Count -ne 0) {
            throw "pydantic-proof accepts no arguments"
        }
        $pydanticProof = (
            "from pydantic.plugin import _loader;" +
            "_loader.importlib_metadata.distributions=" +
            "lambda:(_ for _ in ()).throw(RuntimeError('plugin discovery ran'));" +
            "assert tuple(_loader.get_plugins())==()"
        )
        $uvArguments = $runPrefix + @(
            $pythonExecutable,
            "-I",
            "-B",
            "-c",
            $pydanticProof
        )
    }
    "build" {
        if ($tail.Count -ne 0) {
            throw "build accepts no arguments"
        }
        $uvArguments = $uvBaseArguments + @(
            "--offline",
            "build",
            "--no-build-isolation",
            "--python",
            $pythonExecutable
        )
    }
    default {
        throw "Unknown invoke-uv operation: $operation"
    }
}

$nativeExitCode = 1
$environmentNamesToRemove = @(
    "UV_PROJECT",
    "UV_PROJECT_ENVIRONMENT",
    "UV_WORKING_DIR",
    "UV_CONFIG_FILE",
    "UV_NO_CONFIG",
    "UV_PYTHON",
    "UV_PYTHON_INSTALL_DIR",
    "UV_PYTHON_BIN_DIR",
    "UV_PYTHON_DOWNLOADS",
    "UV_MANAGED_PYTHON",
    "UV_NO_MANAGED_PYTHON",
    "UV_NO_PROJECT",
    "UV_ACTIVE",
    "UV_ENV_FILE",
    "UV_NO_ENV_FILE",
    "UV_OFFLINE",
    "UV_NO_SYNC",
    "UV_FROZEN",
    "UV_LOCKED",
    "UV_ISOLATED",
    "UV_NO_DEV",
    "UV_NO_DEFAULT_GROUPS",
    "UV_NO_GROUP",
    "UV_NO_INSTALL_LOCAL",
    "UV_NO_INSTALL_PROJECT",
    "UV_NO_INSTALL_WORKSPACE",
    "UV_NO_EDITABLE",
    "UV_BUILD_CONSTRAINT",
    "UV_NO_VERIFY_HASHES",
    "UV_REQUIRE_HASHES",
    "UV_CACHE_DIR",
    "UV_COMPILE_BYTECODE",
    "UV_EXCLUDE_NEWER",
    "UV_FORK_STRATEGY",
    "UV_INDEX_STRATEGY",
    "UV_INSECURE_HOST",
    "UV_LINK_MODE",
    "UV_NO_BINARY",
    "UV_NO_BINARY_PACKAGE",
    "UV_NO_BUILD",
    "UV_NO_BUILD_ISOLATION",
    "UV_NO_BUILD_PACKAGE",
    "UV_NO_CACHE",
    "UV_NO_PROGRESS",
    "UV_NO_SOURCES",
    "UV_NO_SOURCES_PACKAGE",
    "UV_PRERELEASE",
    "UV_RESOLUTION",
    "UV_SYSTEM_CERTS",
    "UV_INDEX",
    "UV_DEFAULT_INDEX",
    "UV_INDEX_URL",
    "UV_EXTRA_INDEX_URL",
    "UV_FIND_LINKS",
    "UV_KEYRING_PROVIDER",
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONSTARTUP",
    "PYTHONWARNINGS",
    "PYTHONBREAKPOINT",
    "PYTHONPLATLIBDIR",
    "PYTHONEXECUTABLE",
    "__PYVENV_LAUNCHER__",
    "PYTHONUSERBASE",
    "PYTHONSAFEPATH",
    "PYTHONHASHSEED",
    "PYTHONPYCACHEPREFIX",
    "PYTHONNOUSERSITE",
    "PYTHONCASEOK",
    "PYTHONOPTIMIZE",
    "PYTHONDEBUG",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONUNBUFFERED",
    "PYTHONVERBOSE",
    "PYTHONMALLOC",
    "PYTHONMALLOCSTATS",
    "PYTHONTRACEMALLOC",
    "PYTHONPROFILEIMPORTTIME",
    "PYTHONFAULTHANDLER",
    "PYTHONASYNCIODEBUG",
    "PYTHONUTF8",
    "PYTHONIOENCODING",
    "PYTHONLEGACYWINDOWSSTDIO",
    "PYTHONLEGACYWINDOWSFSENCODING",
    "PYTHONCOERCECLOCALE",
    "PYTHONDEVMODE",
    "PYTHONWARNDEFAULTENCODING",
    "PYTHONNODEBUGRANGES",
    "PYTHONINTMAXSTRDIGITS",
    "PYTEST_ADDOPTS",
    "PYTEST_PLUGINS",
    "COVERAGE_PROCESS_START",
    "COVERAGE_PROCESS_CONFIG",
    "COVERAGE_RCFILE",
    "COVERAGE_FILE",
    "COVERAGE_FORCE_CONFIG",
    "COVERAGE_CORE",
    "COVERAGE_DEBUG",
    "COVERAGE_DEBUG_CALLS",
    "COVERAGE_DEBUG_FILE",
    "COVERAGE_COVERAGE",
    "COVERAGE_TESTING",
    "COVERAGE_AST_DUMP",
    "COVERAGE_TRACK_ARCS",
    "COVERAGE_SYSMON_LOG",
    "COVERAGE_SYSMON_STATS",
    "COV_CORE_SOURCE",
    "COV_CORE_CONFIG",
    "COV_CORE_DATAFILE",
    "COV_CORE_BRANCH",
    "COV_CORE_CONTEXT",
    "MYPYPATH"
)

Push-Location -LiteralPath $repositoryRoot
try {
    foreach ($environmentName in $environmentNamesToRemove) {
        [System.Environment]::SetEnvironmentVariable(
            $environmentName,
            $null,
            [System.EnvironmentVariableTarget]::Process
        )
    }
    $env:PYDANTIC_DISABLE_PLUGINS = "__all__"
    $uvCommands = @(
        Get-Command uv.exe -CommandType Application -All -ErrorAction Stop
    )
    if ($uvCommands.Count -ne 1) {
        throw "Exactly one uv.exe application must be resolvable"
    }
    $uvExecutable = [System.IO.Path]::GetFullPath($uvCommands[0].Source)
    if ([string]::IsNullOrWhiteSpace($uvExecutable)) {
        throw "Unable to resolve uv.exe to an absolute application path"
    }
    & $uvExecutable @uvArguments
    $nativeExitCode = $LASTEXITCODE
}
finally {
    Remove-Item -LiteralPath Env:\PYDANTIC_DISABLE_PLUGINS -ErrorAction SilentlyContinue
    Pop-Location
}

exit $nativeExitCode
```

The launcher is always executed in a new `powershell -File` child and is never
dot-sourced. It resolves and enters the repository root before invoking uv,
then restores its child location and removes the fixed variable in `finally`;
neither cleanup can alter the controller's environment or location. It removes
only the fixed literal uv/Python/test/coverage selection-variable names without
reading, saving, enumerating, or restoring their values. Every ordinary
profile pins the absolute repository and project, ignores ambient uv config,
requires managed Python 3.12 without downloads, and is offline; run profiles
also disable synchronization and dotenv loading. It validates absolute
repository `.venv\\Scripts` Python, Ruff, and console-script paths, rejects
missing or reparse-point path segments, and passes only those commands after
uv's `--` separator. Every pytest profile disables entry-point autoload,
enables only `pytest_cov.plugin`, and pins its configuration to the absolute
repository `pyproject.toml`; the bootstrap profile owns its fixed file,
expression, and quiet flag. `schema-generate-write` alone may pass the exact
repository `schemas` leaf while it is absent so the generator can create it;
all existing ancestors and any existing leaf remain containment- and
reparse-checked, while schema check/distribution still require the leaf.
Focused targets are normalized, physically present, repository-contained paths
with no reparse-point ancestor. Arbitrary tool forwarding,
Python, `-c`, `-m`, package installation, caller-selected scripts, and
caller-selected uv operations are impossible. The only Python operations are
closed profiles for schema generation, schema distribution, module CLI version
acceptance, and the fixed Pydantic proof. `pytest-focused` alone accepts a
closed grammar of normalized repository-relative targets under `tests/`, the
exact optional `-o addopts=` pair, and a final optional `-q`. `lock-acquire`
and `sync-acquire` are non-offline only because their invocation is itself the
exact one-time operation requiring explicit user approval; they are never
verification commands.

Create `tests/safety/test_uv_launcher.py` in Task 1 with exactly:

```python
from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
import subprocess
from base64 import b64decode
from pathlib import Path

import pytest

_EXPECTED_NORMALIZED_SHA256 = (
    "1aee7c257068e9fd68ba741f24dd1e6a02fca7592a609185cd1afffab7cd8041"
)
_ALLOWED_COMMANDS = {
    "<dynamic>",
    "Get-Command",
    "Get-Item",
    "Join-Path",
    "Pop-Location",
    "Push-Location",
    "Remove-Item",
    "Resolve-Path",
    "Resolve-ClosedRepositoryPath",
    "Resolve-ClosedSchemaWriteDirectory",
    "Set-StrictMode",
}
_PURGED_ENVIRONMENT_NAMES = (
    "UV_PROJECT",
    "UV_PROJECT_ENVIRONMENT",
    "UV_WORKING_DIR",
    "UV_CONFIG_FILE",
    "UV_NO_CONFIG",
    "UV_PYTHON",
    "UV_PYTHON_INSTALL_DIR",
    "UV_PYTHON_BIN_DIR",
    "UV_PYTHON_DOWNLOADS",
    "UV_MANAGED_PYTHON",
    "UV_NO_MANAGED_PYTHON",
    "UV_NO_PROJECT",
    "UV_ACTIVE",
    "UV_ENV_FILE",
    "UV_NO_ENV_FILE",
    "UV_OFFLINE",
    "UV_NO_SYNC",
    "UV_FROZEN",
    "UV_LOCKED",
    "UV_ISOLATED",
    "UV_NO_DEV",
    "UV_NO_DEFAULT_GROUPS",
    "UV_NO_GROUP",
    "UV_NO_INSTALL_LOCAL",
    "UV_NO_INSTALL_PROJECT",
    "UV_NO_INSTALL_WORKSPACE",
    "UV_NO_EDITABLE",
    "UV_BUILD_CONSTRAINT",
    "UV_NO_VERIFY_HASHES",
    "UV_REQUIRE_HASHES",
    "UV_CACHE_DIR",
    "UV_COMPILE_BYTECODE",
    "UV_EXCLUDE_NEWER",
    "UV_FORK_STRATEGY",
    "UV_INDEX_STRATEGY",
    "UV_INSECURE_HOST",
    "UV_LINK_MODE",
    "UV_NO_BINARY",
    "UV_NO_BINARY_PACKAGE",
    "UV_NO_BUILD",
    "UV_NO_BUILD_ISOLATION",
    "UV_NO_BUILD_PACKAGE",
    "UV_NO_CACHE",
    "UV_NO_PROGRESS",
    "UV_NO_SOURCES",
    "UV_NO_SOURCES_PACKAGE",
    "UV_PRERELEASE",
    "UV_RESOLUTION",
    "UV_SYSTEM_CERTS",
    "UV_INDEX",
    "UV_DEFAULT_INDEX",
    "UV_INDEX_URL",
    "UV_EXTRA_INDEX_URL",
    "UV_FIND_LINKS",
    "UV_KEYRING_PROVIDER",
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONSTARTUP",
    "PYTHONWARNINGS",
    "PYTHONBREAKPOINT",
    "PYTHONPLATLIBDIR",
    "PYTHONEXECUTABLE",
    "__PYVENV_LAUNCHER__",
    "PYTHONUSERBASE",
    "PYTHONSAFEPATH",
    "PYTHONHASHSEED",
    "PYTHONPYCACHEPREFIX",
    "PYTHONNOUSERSITE",
    "PYTHONCASEOK",
    "PYTHONOPTIMIZE",
    "PYTHONDEBUG",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONUNBUFFERED",
    "PYTHONVERBOSE",
    "PYTHONMALLOC",
    "PYTHONMALLOCSTATS",
    "PYTHONTRACEMALLOC",
    "PYTHONPROFILEIMPORTTIME",
    "PYTHONFAULTHANDLER",
    "PYTHONASYNCIODEBUG",
    "PYTHONUTF8",
    "PYTHONIOENCODING",
    "PYTHONLEGACYWINDOWSSTDIO",
    "PYTHONLEGACYWINDOWSFSENCODING",
    "PYTHONCOERCECLOCALE",
    "PYTHONDEVMODE",
    "PYTHONWARNDEFAULTENCODING",
    "PYTHONNODEBUGRANGES",
    "PYTHONINTMAXSTRDIGITS",
    "PYTEST_ADDOPTS",
    "PYTEST_PLUGINS",
    "COVERAGE_PROCESS_START",
    "COVERAGE_PROCESS_CONFIG",
    "COVERAGE_RCFILE",
    "COVERAGE_FILE",
    "COVERAGE_FORCE_CONFIG",
    "COVERAGE_CORE",
    "COVERAGE_DEBUG",
    "COVERAGE_DEBUG_CALLS",
    "COVERAGE_DEBUG_FILE",
    "COVERAGE_COVERAGE",
    "COVERAGE_TESTING",
    "COVERAGE_AST_DUMP",
    "COVERAGE_TRACK_ARCS",
    "COVERAGE_SYSMON_LOG",
    "COVERAGE_SYSMON_STATS",
    "COV_CORE_SOURCE",
    "COV_CORE_CONFIG",
    "COV_CORE_DATAFILE",
    "COV_CORE_BRANCH",
    "COV_CORE_CONTEXT",
    "MYPYPATH",
)
_PYDANTIC_PROOF = (
    "from pydantic.plugin import _loader;"
    "_loader.importlib_metadata.distributions="
    "lambda:(_ for _ in ()).throw(RuntimeError('plugin discovery ran'));"
    "assert tuple(_loader.get_plugins())==()"
)
_PYTHON = "<PYTHON>"
_RUFF = "<RUFF>"
_CLI = "<CLI>"
_ROOT = "<ROOT>"


def _normalized_source(path: Path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    return "\n".join(line.rstrip() for line in lines) + "\n"


def _powershell() -> str:
    executable = shutil.which("powershell")
    assert executable is not None
    return executable


def _run_launcher(
    repository_root: Path,
    arguments: list[str],
    *,
    environment: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - reviewed fixed PowerShell boundary
        [
            _powershell(),
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(repository_root / "scripts" / "invoke-uv.ps1"),
            *arguments,
        ],
        cwd=repository_root if cwd is None else cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        shell=False,
    )


def _create_junction(path: Path, target: Path) -> None:
    script = (
        "$payload=[Console]::In.ReadToEnd()|ConvertFrom-Json;"
        "New-Item -ItemType Junction -Path ([string]$payload.path) "
        "-Target ([string]$payload.target)|Out-Null"
    )
    created = subprocess.run(  # noqa: S603 - reviewed fixed PowerShell boundary
        [_powershell(), "-NoProfile", "-Command", script],
        input=json.dumps({"path": str(path), "target": str(target)}),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
    )
    assert created.returncode == 0, created.stderr


def _powershell_command_records(
    path: Path,
    repository_root: Path,
) -> tuple[tuple[str, str], ...]:
    parser = (
        "$path=[Console]::In.ReadLine();$tokens=$null;$errors=$null;"
        "$ast=[System.Management.Automation.Language.Parser]::ParseFile("
        "$path,[ref]$tokens,[ref]$errors);"
        "if($errors.Count-ne 0){exit 91};"
        "$records=@($ast.FindAll({param($node) $node -is "
        "[System.Management.Automation.Language.CommandAst]},$true)|"
        "ForEach-Object{$name=$_.GetCommandName();"
        "if($null-eq$name){$name='<dynamic>'};"
        "[pscustomobject]@{name=$name;extent=$_.Extent.Text}});"
        "$records|ConvertTo-Json -Compress"
    )
    completed = subprocess.run(  # noqa: S603 - reviewed fixed parser boundary
        [_powershell(), "-NoProfile", "-Command", parser],
        cwd=repository_root,
        input=f"{path}\n",
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
    )
    assert completed.returncode == 0, completed.stderr
    parsed = json.loads(completed.stdout)
    records = [parsed] if isinstance(parsed, dict) else parsed
    return tuple((record["name"], record["extent"]) for record in records)


def _fake_uv_environment(tmp_path: Path) -> dict[str, str]:
    source = tmp_path / "FakeUv.cs"
    source.write_text(
        """
using System;
using System.Text;

public static class FakeUv
{
    private static string Encode(string value)
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
    }

    public static int Main(string[] args)
    {
        Console.WriteLine("cwd=" + Encode(Environment.CurrentDirectory));
        foreach (string argument in args)
        {
            Console.WriteLine("arg=" + Encode(argument));
        }
        string[] names = Environment.GetEnvironmentVariable("FAKE_UV_ENV_NAMES")
            .Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (string name in names)
        {
            string value = Environment.GetEnvironmentVariable(name);
            Console.WriteLine(
                "env=" + name + ":" + (value == null ? "<missing>" : Encode(value))
            );
        }
        foreach (string argument in args)
        {
            if (argument.Contains("__exit37__"))
            {
                return 37;
            }
        }
        return 0;
    }
}
""".lstrip(),
        encoding="utf-8",
    )
    fake_uv = tmp_path / "uv.exe"
    compiler = (
        "$payload=[Console]::In.ReadToEnd()|ConvertFrom-Json;"
        "$source=[IO.File]::ReadAllText([string]$payload.source);"
        "Add-Type -TypeDefinition $source "
        "-OutputAssembly ([string]$payload.output) -OutputType ConsoleApplication"
    )
    completed = subprocess.run(  # noqa: S603 - reviewed fixed compiler boundary
        [_powershell(), "-NoProfile", "-Command", compiler],
        cwd=tmp_path,
        input=json.dumps({"source": str(source), "output": str(fake_uv)}),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
    )
    assert completed.returncode == 0, completed.stderr
    environment = {
        "PATH": str(tmp_path),
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        "SystemRoot": r"C:\Windows",
        "WINDIR": r"C:\Windows",
        "TEMP": str(tmp_path),
        "TMP": str(tmp_path),
        "FAKE_UV_ENV_NAMES": ";".join(
            (*_PURGED_ENVIRONMENT_NAMES, "PYDANTIC_DISABLE_PLUGINS")
        ),
    }
    for index, name in enumerate(_PURGED_ENVIRONMENT_NAMES):
        environment[name] = f"hostile-{index}"
    environment["PYDANTIC_DISABLE_PLUGINS"] = "ambient-test-value"
    return environment


def _parse_fake_uv(stdout: str) -> dict[str, object]:
    result: dict[str, object] = {"argv": [], "environment": {}}
    for line in stdout.splitlines():
        kind, payload = line.split("=", 1)
        if kind == "cwd":
            result["cwd"] = b64decode(payload).decode()
        elif kind == "arg":
            argv = result["argv"]
            assert isinstance(argv, list)
            argv.append(b64decode(payload).decode())
        else:
            name, encoded = payload.split(":", 1)
            environment = result["environment"]
            assert isinstance(environment, dict)
            environment[name] = (
                None if encoded == "<missing>" else b64decode(encoded).decode()
            )
    return result


def test_launcher_has_exact_reviewed_normalized_source(repository_root: Path) -> None:
    launcher = repository_root / "scripts" / "invoke-uv.ps1"
    source = _normalized_source(launcher)
    digest = hashlib.sha256(source.encode()).hexdigest()
    assert digest == _EXPECTED_NORMALIZED_SHA256
    assert source.count('$env:PYDANTIC_DISABLE_PLUGINS = "__all__"') == 1
    assert "Get-ChildItem Env:" not in source
    assert "Get-Item Env:" not in source
    assert "GetEnvironmentVariable" not in source
    assert source.count("[System.Environment]::SetEnvironmentVariable(") == 1
    assert "Get-Command uv.exe -CommandType Application -All" in source
    assert "$uvCommands.Count -ne 1" in source
    assert "[System.IO.Path]::GetFullPath($uvCommands[0].Source)" in source
    assert "& $uvExecutable @uvArguments" in source
    assert source.count('"--disable-plugin-autoload"') == 1
    assert source.count('"--cov-config=$coverageConfig"') == 1
    assert source.count('"pytest-launcher-bootstrap"') == 1
    assert "function Resolve-ClosedRepositoryPath" in source
    assert "function Resolve-ClosedSchemaWriteDirectory" in source
    assert source.count("[System.IO.FileAttributes]::ReparsePoint") == 4
    assert 'Join-Path $repositoryRoot ".venv\\Scripts\\python.exe"' in source
    block_start = source.index("$environmentNamesToRemove = @(")
    block_end = source.index("\n)\n\nPush-Location", block_start)
    declared_names = tuple(
        line.strip().removesuffix(",").strip('"')
        for line in source[block_start:block_end].splitlines()[1:]
    )
    assert declared_names == _PURGED_ENVIRONMENT_NAMES
    for name in declared_names:
        assert f"$env:{name}" not in source


def test_launcher_ast_has_only_closed_commands(repository_root: Path) -> None:
    launcher = repository_root / "scripts" / "invoke-uv.ps1"
    records = _powershell_command_records(launcher, repository_root)
    assert {name for name, _ in records} == _ALLOWED_COMMANDS
    assert tuple(extent for name, extent in records if name == "<dynamic>") == (
        "& $uvExecutable @uvArguments",
    )


@pytest.fixture(scope="module")
def fake_uv_environment(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    return _fake_uv_environment(tmp_path_factory.mktemp("fake-uv"))


@pytest.fixture
def launcher_repository(
    tmp_path: Path,
    repository_root: Path,
) -> Path:
    root = tmp_path / "launcher-repository"
    for directory in (
        root / ".venv" / "Scripts",
        root / "dist",
        root / "schemas",
        root / "scripts",
        root / "tests" / "safety",
        root / "tests" / "unit" / "domain",
    ):
        directory.mkdir(parents=True, exist_ok=True)
    shutil.copy2(
        repository_root / "scripts" / "invoke-uv.ps1",
        root / "scripts" / "invoke-uv.ps1",
    )
    for path in (
        root / ".venv" / "Scripts" / "python.exe",
        root / ".venv" / "Scripts" / "ruff.exe",
        root / ".venv" / "Scripts" / "crypto-lab.exe",
        root / "scripts" / "generate_schemas.py",
        root / "scripts" / "verify_schema_distribution.py",
        root / "tests" / "__exit37__.py",
        root / "tests" / "safety" / "test_uv_launcher.py",
        root / "tests" / "unit" / "domain" / "test_records.py",
        root / "pyproject.toml",
    ):
        path.touch()
    return root


def _base_arguments(repository_root: Path) -> list[str]:
    root = str(repository_root)
    return [
        "--directory",
        root,
        "--project",
        root,
        "--no-config",
        "--managed-python",
        "--no-python-downloads",
    ]


def _run_arguments(repository_root: Path, *arguments: str) -> list[str]:
    python = str(repository_root / ".venv" / "Scripts" / "python.exe")
    return [
        *_base_arguments(repository_root),
        "--offline",
        "run",
        "--no-sync",
        "--no-env-file",
        "--python",
        python,
        "--",
        *arguments,
    ]


@pytest.mark.parametrize(
    ("arguments", "command"),
    [
        (["lock-check"], ["--offline", "lock", "--check", "--python", _PYTHON]),
        (
            ["lock-resolve-offline"],
            ["--offline", "lock", "--python", _PYTHON],
        ),
        (
            ["sync"],
            [
                "--offline",
                "sync",
                "--frozen",
                "--no-build-isolation",
                "--python",
                _PYTHON,
            ],
        ),
        (["lock-acquire"], ["lock", "--python", _PYTHON]),
        (
            ["sync-acquire"],
            [
                "sync",
                "--frozen",
                "--no-install-project",
                "--no-build-isolation",
                "--python",
                _PYTHON,
            ],
        ),
        (["ruff-format-all"], ["RUN", _RUFF, "format", "--check", "."]),
        (["ruff-check-all"], ["RUN", _RUFF, "check", "."]),
        (
            ["mypy-all"],
            ["RUN", _PYTHON, "-I", "-B", "-m", "mypy"],
        ),
        (
            ["pytest-all"],
            [
                "RUN",
                _PYTHON,
                "-I",
                "-B",
                "-m",
                "pytest",
                "--disable-plugin-autoload",
                "-p",
                "pytest_cov.plugin",
                f"--cov-config={_ROOT}\\pyproject.toml",
            ],
        ),
        (
            ["pytest-launcher-bootstrap"],
            [
                "RUN",
                _PYTHON,
                "-I",
                "-B",
                "-m",
                "pytest",
                "--disable-plugin-autoload",
                "-p",
                "pytest_cov.plugin",
                f"--cov-config={_ROOT}\\pyproject.toml",
                "-o",
                "addopts=",
                f"{_ROOT}\\tests\\safety\\test_uv_launcher.py",
                "-k",
                "launcher and not validation_libraries and not pydantic",
                "-q",
            ],
        ),
        (
            ["pytest-focused", "tests/safety/test_uv_launcher.py", "-q"],
            [
                "RUN",
                _PYTHON,
                "-I",
                "-B",
                "-m",
                "pytest",
                "--disable-plugin-autoload",
                "-p",
                "pytest_cov.plugin",
                f"--cov-config={_ROOT}\\pyproject.toml",
                f"{_ROOT}\\tests\\safety\\test_uv_launcher.py",
                "-q",
            ],
        ),
        (
            [
                "pytest-focused",
                "-o",
                "addopts=",
                "tests/unit/domain/test_records.py::test_valid",
                "tests/safety/test_uv_launcher.py",
                "-q",
            ],
            [
                "RUN",
                _PYTHON,
                "-I",
                "-B",
                "-m",
                "pytest",
                "--disable-plugin-autoload",
                "-p",
                "pytest_cov.plugin",
                f"--cov-config={_ROOT}\\pyproject.toml",
                "-o",
                "addopts=",
                f"{_ROOT}\\tests\\unit\\domain\\test_records.py::test_valid",
                f"{_ROOT}\\tests\\safety\\test_uv_launcher.py",
                "-q",
            ],
        ),
        (
            ["schema-generate-write"],
            [
                "RUN",
                _PYTHON,
                "-I",
                "-B",
                f"{_ROOT}\\scripts\\generate_schemas.py",
                "--output",
                f"{_ROOT}\\schemas",
                "--write",
            ],
        ),
        (
            ["schema-generate-check"],
            [
                "RUN",
                _PYTHON,
                "-I",
                "-B",
                f"{_ROOT}\\scripts\\generate_schemas.py",
                "--output",
                f"{_ROOT}\\schemas",
                "--check",
            ],
        ),
        (
            ["schema-distribution"],
            [
                "RUN",
                _PYTHON,
                "-I",
                "-B",
                f"{_ROOT}\\scripts\\verify_schema_distribution.py",
                "--source",
                f"{_ROOT}\\schemas",
                "--dist",
                f"{_ROOT}\\dist",
            ],
        ),
        (["cli-version"], ["RUN", _CLI, "--version"]),
        (
            ["cli-module-version"],
            [
                "RUN",
                _PYTHON,
                "-I",
                "-B",
                "-m",
                "crypto_lab.cli",
                "--version",
            ],
        ),
        (["cli-help"], ["RUN", _CLI]),
        (["cli-unknown"], ["RUN", _CLI, "--unknown"]),
        (
            ["pydantic-proof"],
            ["RUN", _PYTHON, "-I", "-B", "-c", _PYDANTIC_PROOF],
        ),
        (
            ["build"],
            [
                "--offline",
                "build",
                "--no-build-isolation",
                "--python",
                _PYTHON,
            ],
        ),
    ],
)
def test_launcher_synthesizes_only_exact_offline_uv_forms_and_pins_root(
    launcher_repository: Path,
    tmp_path: Path,
    fake_uv_environment: dict[str, str],
    arguments: list[str],
    command: list[str],
) -> None:
    environment = fake_uv_environment.copy()
    completed = _run_launcher(
        launcher_repository,
        arguments,
        environment=environment,
        cwd=tmp_path,
    )
    assert completed.returncode == 0, completed.stderr
    replacements = {
        _PYTHON: str(launcher_repository / ".venv" / "Scripts" / "python.exe"),
        _RUFF: str(launcher_repository / ".venv" / "Scripts" / "ruff.exe"),
        _CLI: str(launcher_repository / ".venv" / "Scripts" / "crypto-lab.exe"),
        _ROOT: str(launcher_repository),
    }
    rendered = [
        next(
            (
                argument.replace(marker, value)
                for marker, value in replacements.items()
                if marker in argument
            ),
            argument,
        )
        for argument in command
    ]
    expected = (
        _run_arguments(launcher_repository, *rendered[1:])
        if command[0] == "RUN"
        else [*_base_arguments(launcher_repository), *rendered]
    )
    assert _parse_fake_uv(completed.stdout) == {
        "argv": expected,
        "cwd": str(launcher_repository),
        "environment": {
            **dict.fromkeys(_PURGED_ENVIRONMENT_NAMES),
            "PYDANTIC_DISABLE_PLUGINS": "__all__",
        },
    }
    for index, name in enumerate(_PURGED_ENVIRONMENT_NAMES):
        assert environment[name] == f"hostile-{index}"
    assert environment["PYDANTIC_DISABLE_PLUGINS"] == "ambient-test-value"


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["lock-check", "extra"],
        ["lock-resolve-offline", "extra"],
        ["sync", "extra"],
        ["lock-acquire", "extra"],
        ["sync-acquire", "extra"],
        ["build", "extra"],
        ["ruff-format-all", "extra"],
        ["ruff-check-all", "extra"],
        ["mypy-all", "extra"],
        ["pytest-all", "extra"],
        ["pytest-launcher-bootstrap", "extra"],
        ["run", "python", "-m", "pip"],
        ["pytest-focused"],
        ["pytest-focused", r"C:\outside\test.py"],
        ["pytest-focused", r"\\server\share\test.py"],
        ["pytest-focused", "/outside/test.py"],
        ["pytest-focused", "tests/../outside.py"],
        ["pytest-focused", "tests//test_bad.py"],
        ["pytest-focused", "tests/*.py"],
        ["pytest-focused", "tests/missing.py"],
        ["pytest-focused", "tests/path with spaces/test_bad.py"],
        ["pytest-focused", "tests/test_bad.py::test_name::nested"],
        ["pytest-focused", "-p", "plugin"],
        ["pytest-focused", "--pyargs", "package"],
        ["pytest-focused", "--rootdir", "outside"],
        ["pytest-focused", "--import-mode=prepend", "tests/test_bad.py"],
        ["pytest-focused", "-c", "outside.ini"],
        ["pytest-focused", "-o", "not-addopts", "tests/test_bad.py"],
        ["pytest-focused", "tests/test_bad.py", "-q", "tests/test_more.py"],
        ["schema-generate-write", "extra"],
        ["schema-generate-check", "extra"],
        ["schema-distribution", "extra"],
        ["cli-version", "extra"],
        ["cli-module-version", "extra"],
        ["cli-help", "extra"],
        ["cli-unknown", "extra"],
        ["pydantic-proof", "extra"],
        ["unknown"],
    ],
)
def test_launcher_rejects_every_unapproved_form(
    launcher_repository: Path,
    tmp_path: Path,
    fake_uv_environment: dict[str, str],
    arguments: list[str],
) -> None:
    completed = _run_launcher(
        launcher_repository,
        arguments,
        environment=fake_uv_environment,
        cwd=tmp_path,
    )
    assert completed.returncode != 0
    assert completed.stdout == ""


def test_launcher_rejects_ambiguous_uv_application_resolution(
    launcher_repository: Path,
    tmp_path: Path,
    fake_uv_environment: dict[str, str],
) -> None:
    first_directory = Path(fake_uv_environment["PATH"])
    second_directory = tmp_path / "second-uv"
    second_directory.mkdir()
    shutil.copy2(first_directory / "uv.exe", second_directory / "uv.exe")
    environment = fake_uv_environment.copy()
    environment["PATH"] = f"{first_directory}{os.pathsep}{second_directory}"
    completed = _run_launcher(
        launcher_repository,
        ["lock-check"],
        environment=environment,
        cwd=tmp_path,
    )
    assert completed.returncode != 0
    assert completed.stdout == ""
    assert "Exactly one uv.exe application" in completed.stderr


def test_launcher_rejects_reparse_point_test_target(
    launcher_repository: Path,
    tmp_path: Path,
    fake_uv_environment: dict[str, str],
) -> None:
    outside = tmp_path / "outside-tests"
    outside.mkdir()
    (outside / "test_escape.py").touch()
    link = launcher_repository / "tests" / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Windows test principal cannot create a symbolic link")
    completed = _run_launcher(
        launcher_repository,
        ["pytest-focused", "tests/linked/test_escape.py"],
        environment=fake_uv_environment,
        cwd=tmp_path,
    )
    assert completed.returncode != 0
    assert completed.stdout == ""
    assert "reparse point" in completed.stderr


def test_launcher_rejects_junction_target_without_optional_privilege(
    launcher_repository: Path,
    tmp_path: Path,
    fake_uv_environment: dict[str, str],
) -> None:
    outside = tmp_path / "junction-target"
    outside.mkdir()
    (outside / "test_escape.py").touch()
    junction = launcher_repository / "tests" / "junction"
    _create_junction(junction, outside)
    completed = _run_launcher(
        launcher_repository,
        ["pytest-focused", "tests/junction/test_escape.py"],
        environment=fake_uv_environment,
        cwd=tmp_path,
    )
    assert completed.returncode != 0
    assert completed.stdout == ""
    assert "reparse point" in completed.stderr


def test_schema_write_accepts_only_the_absent_exact_schema_leaf(
    launcher_repository: Path,
    tmp_path: Path,
    fake_uv_environment: dict[str, str],
) -> None:
    schema_directory = launcher_repository / "schemas"
    shutil.rmtree(schema_directory)
    completed = _run_launcher(
        launcher_repository,
        ["schema-generate-write"],
        environment=fake_uv_environment,
        cwd=tmp_path,
    )
    assert completed.returncode == 0, completed.stderr
    parsed = _parse_fake_uv(completed.stdout)
    argv = parsed["argv"]
    assert isinstance(argv, list)
    assert str(schema_directory) in argv
    assert not schema_directory.exists()


def test_schema_write_rejects_an_existing_reparse_point_leaf(
    launcher_repository: Path,
    tmp_path: Path,
    fake_uv_environment: dict[str, str],
) -> None:
    schema_directory = launcher_repository / "schemas"
    shutil.rmtree(schema_directory)
    outside = tmp_path / "outside-schemas"
    outside.mkdir()
    _create_junction(schema_directory, outside)
    completed = _run_launcher(
        launcher_repository,
        ["schema-generate-write"],
        environment=fake_uv_environment,
        cwd=tmp_path,
    )
    assert completed.returncode != 0
    assert completed.stdout == ""
    assert "reparse point" in completed.stderr


def test_launcher_propagates_native_exit_code(
    launcher_repository: Path,
    tmp_path: Path,
    fake_uv_environment: dict[str, str],
) -> None:
    completed = _run_launcher(
        launcher_repository,
        ["pytest-focused", "tests/__exit37__.py"],
        environment=fake_uv_environment,
        cwd=tmp_path,
    )
    assert completed.returncode == 37


def test_validation_libraries_are_available() -> None:
    for module_name in ("hypothesis", "jsonschema", "pydantic"):
        assert importlib.import_module(module_name) is not None


def test_launcher_disables_real_pydantic_plugin_discovery_and_leaves_parent_unchanged(
    repository_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("pydantic")
    monkeypatch.setenv("PYDANTIC_DISABLE_PLUGINS", "ambient-test-value")
    completed = _run_launcher(repository_root, ["pydantic-proof"])
    assert completed.returncode == 0, completed.stderr
    assert os.environ["PYDANTIC_DISABLE_PLUGINS"] == "ambient-test-value"


@pytest.mark.parametrize(
    "mutation",
    [
        "bitsadmin /transfer forbidden https://example.invalid/a out",
        "certutil -urlcache -split -f https://example.invalid/a out",
        "[System.Net.Http.HttpClient]::new()",
        "$executable = 'uv'; & $executable --version",
    ],
)
def test_mutations_fail_exact_source_and_closed_command_guards(
    repository_root: Path,
    tmp_path: Path,
    mutation: str,
) -> None:
    source = _normalized_source(repository_root / "scripts" / "invoke-uv.ps1")
    mutated = tmp_path / "mutated-launcher.ps1"
    mutated.write_text(f"{source}{mutation}\n", encoding="utf-8")
    digest = hashlib.sha256(_normalized_source(mutated).encode()).hexdigest()
    assert digest != _EXPECTED_NORMALIZED_SHA256
    if mutation.startswith("$executable") or mutation.startswith(
        ("bitsadmin", "certutil")
    ):
        records = _powershell_command_records(mutated, repository_root)
        assert {name for name, _ in records} != _ALLOWED_COMMANDS or tuple(
            extent for name, extent in records if name == "<dynamic>"
        ) != ("& $uvExecutable @uvArguments",)
```

The four `S603` suppressions sit only on reviewed, absolute-PowerShell,
argument-array subprocess boundaries. Launcher behavior children have a
30-second test timeout; the parser, compiler, and junction helpers retain a
ten-second timeout. Every subprocess uses `shell=False`. The test proves absolute `uv.exe` resolution,
root/project pinning, exact selectors, zero-, one-, and multi-tail profile
vectors, native exit propagation, fixed child control, hostile selection and
test-tooling variable removal without value reads, parent isolation, external
pytest path/option rejection, exact normalized source, and closed PowerShell
commands. Intentional network/dynamic-execution strings occur only
as the four exact mutation parameters in this reviewed test body; Task 9 runs
the test and searches application source separately, so it never manually
classifies broad grep output from fixtures.

Replace `scripts/verify.ps1` with exactly:

```powershell
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$verificationExitCode = 0
$repositoryRoot = (
    Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath "..")
).Path

function Assert-NativeSuccess {
    param([string]$CommandLabel)

    if ($LASTEXITCODE -ne 0) {
        $script:verificationExitCode = $LASTEXITCODE
        throw "$CommandLabel failed with exit code $LASTEXITCODE"
    }
}

Push-Location -LiteralPath $repositoryRoot
try {
    Write-Host "`n==> Check lockfile consistency"
    & powershell -NoProfile -ExecutionPolicy Bypass -File `
        .\scripts\invoke-uv.ps1 lock-check
    Assert-NativeSuccess "Lockfile check"

    Write-Host "`n==> Sync locked environment"
    & powershell -NoProfile -ExecutionPolicy Bypass -File `
        .\scripts\invoke-uv.ps1 sync
    Assert-NativeSuccess "Locked synchronization"

    Write-Host "`n==> Check formatting"
    & powershell -NoProfile -ExecutionPolicy Bypass -File `
        .\scripts\invoke-uv.ps1 ruff-format-all
    Assert-NativeSuccess "Format check"

    Write-Host "`n==> Run lint checks"
    & powershell -NoProfile -ExecutionPolicy Bypass -File `
        .\scripts\invoke-uv.ps1 ruff-check-all
    Assert-NativeSuccess "Lint check"

    Write-Host "`n==> Run strict type checks"
    & powershell -NoProfile -ExecutionPolicy Bypass -File `
        .\scripts\invoke-uv.ps1 mypy-all
    Assert-NativeSuccess "Type check"

    Write-Host "`n==> Check generated schemas"
    & powershell -NoProfile -ExecutionPolicy Bypass -File `
        .\scripts\invoke-uv.ps1 schema-generate-check
    Assert-NativeSuccess "Generated-schema check"

    Write-Host "`n==> Run test suite"
    & powershell -NoProfile -ExecutionPolicy Bypass -File `
        .\scripts\invoke-uv.ps1 pytest-all
    Assert-NativeSuccess "Test suite"

    Write-Host "`n==> Build package"
    & powershell -NoProfile -ExecutionPolicy Bypass -File `
        .\scripts\invoke-uv.ps1 build
    Assert-NativeSuccess "Package build"

    Write-Host "`n==> Check schema distribution"
    & powershell -NoProfile -ExecutionPolicy Bypass -File `
        .\scripts\invoke-uv.ps1 schema-distribution
    Assert-NativeSuccess "Schema distribution check"

    Write-Host "`n==> Check Git whitespace"
    & git diff --check
    Assert-NativeSuccess "Git whitespace check"
}
catch {
    if ($verificationExitCode -eq 0) {
        $verificationExitCode = 1
    }
    [Console]::Error.WriteLine($_.Exception.Message)
}
finally {
    Pop-Location
}

exit $verificationExitCode
```

This preserves repository-root resolution, first-failure behavior, native
exit-code propagation, and `finally`-based directory restoration. The ten
logical operations remain in the exact documented order. Every uv operation
is closed behind the child launcher; neither script can convert missing cached
packages into a network request or preserve an ambient plugin-control value.

---

### A.7 Verification and user documentation

Replace `docs/development/verification.md` with exactly:

````markdown
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
uses `.venv` through the repository `scripts/invoke-uv.ps1` child launcher.
Stop without installing anything when either prerequisite is absent.

The workflow relies on `.python-version` requesting `3.12`,
`python-preference = "only-managed"` prohibiting system-Python fallback, and
`python-downloads = "manual"` disabling automatic interpreter downloads.

## Locked setup

After `uv.lock` exists, synchronize only from local locked content:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 sync
```

If cached packages are insufficient, stop. Show and obtain one-time approval
for the exact Task 1 `sync-acquire` launcher profile,
then return to the launcher `sync` operation, which expands only to the fixed
offline form. Acquisition is not verification
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
generation checks the closed 11-file registry without writing; distribution
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

The `addopts` override removes the repository-wide coverage threshold only
from a focused diagnostic run. The later complete suite must satisfy the
configured branch-coverage gate.

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
generator targets only the 11 fixed lexical descendants, rejects an existing
symlink root or entry, and refuses every unexpected file without deleting it.
Stage 7 retains physical ancestor reparse-point and volume containment. The
`--check` mode writes nothing and fails on a missing, changed, or unexpected
schema. The distribution check requires one wheel copy under
`crypto_lab/schemas/` and one sdist copy under `schemas/`, with bytes identical
to the reviewed source, and rejects every unexpected payload beneath either
schema prefix.

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
````

Apply this exact Task 8 patch to `README.md`:

```diff
@@
-**Status:** Project 1 foundation
+**Status:** Project 1 Stage 3 implementation under acceptance review
@@
-Crypto Trading Lab is a personal, local-only Windows project for building an engine-neutral research and simulated-trading foundation. Stage 1 supplies only the Python package scaffold, version command, offline safety checks, and local quality workflow.
+Crypto Trading Lab is a personal, local-only Windows project for building an engine-neutral research and simulated-trading foundation. Stage 1 supplies the Python scaffold and offline workflow; Stage 2 records GitNexus as `DISABLED_WITH_EVIDENCE`; Stage 3 adds strict canonical values, explicit configuration, deterministic hashes, dataset metadata, structural descriptors, artifact ownership, and generated schemas without adding an engine or runtime service.
@@
 ## Verification
@@
-The workflow checks that `uv.lock` matches the current project metadata before synchronizing the locked environment, then checks formatting, linting, strict typing, tests and coverage, package builds, and Git whitespace. See [development verification](docs/development/verification.md) for focused commands and the dependency network gate.
+The ten-operation workflow checks the lock and offline synchronization, formatting, linting, strict typing, deterministic schemas, tests and coverage, the offline build, exact schema bytes in both distributions, and Git whitespace. See [development verification](docs/development/verification.md) for focused commands and the dependency network gate.
```

Insert this exact section immediately before `## Verification` in `README.md`:

````markdown
## Explicit configuration and schemas

Stage 3 configuration accepts only compiled defaults, an explicitly named
primary TOML file, an optional explicitly named local override, and allowlisted
typed CLI overrides. It does not inspect environment variables, profiles, home
directories, the current directory, the registry, credentials, or implicit
configuration files.

The reviewed source schemas are generated and checked offline:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 schema-generate-write
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 schema-generate-check
```

The complete verifier checks that exactly those 11 schemas are packaged once
in the wheel and once in the sdist with identical bytes.
````

Task 9 replaces the temporary README status with the exact completed status
only after capturing a clean, fully verified implementation commit. No other
README text changes in Task 9.

---

### A.8 Existing safety tests and Stage 3 boundary test

Replace `tests/unit/test_package_layout.py` with exactly:

```python
"""Test the Stage 1 package layout and bounded fresh-process import guard."""

from __future__ import annotations

import importlib
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path

PACKAGE_MODULES: tuple[str, ...] = (
    "crypto_lab",
    "crypto_lab.domain",
    "crypto_lab.domain.base",
    "crypto_lab.domain.identifiers",
    "crypto_lab.domain.time",
    "crypto_lab.domain.financial",
    "crypto_lab.domain.records",
    "crypto_lab.domain.versioning",
    "crypto_lab.domain.canonical_json",
    "crypto_lab.domain.hashing",
    "crypto_lab.domain.diagnostics",
    "crypto_lab.strategy",
    "crypto_lab.capabilities",
    "crypto_lab.adapters",
    "crypto_lab.adapters.versioning",
    "crypto_lab.adapters.descriptors",
    "crypto_lab.experiments",
    "crypto_lab.datasets",
    "crypto_lab.datasets.models",
    "crypto_lab.datasets.hashing",
    "crypto_lab.artifacts",
    "crypto_lab.artifacts.ownership",
    "crypto_lab.persistence",
    "crypto_lab.process_supervision",
    "crypto_lab.configuration",
    "crypto_lab.configuration.models",
    "crypto_lab.configuration.loader",
    "crypto_lab.configuration.snapshot",
    "crypto_lab.audit",
    "crypto_lab.cli",
    "crypto_lab.cli.main",
    "crypto_lab.cli.__main__",
    "crypto_lab.schema_registry",
)
_IMPORT_SENTINEL = "IMPORT_GUARDS_OK"
_IMPORT_PROBE = """
from __future__ import annotations

import builtins
import http.client
import importlib
import os
import socket
import subprocess
import sys
import urllib.request
import winreg
from pathlib import Path
from typing import NoReturn


def _unexpected_operation(*args: object, **kwargs: object) -> NoReturn:
    del args, kwargs
    raise AssertionError("package import attempted a forbidden side effect")


def _guarded_getenv(key: str, default: object = None) -> str:
    del default
    caller_module = sys._getframe(1).f_globals.get("__name__")
    if (
        key == "PYDANTIC_DISABLE_PLUGINS"
        and caller_module == "pydantic.plugin._loader"
    ):
        return "__all__"
    return _unexpected_operation(key, caller_module)


class ForbiddenEnvironment:
    def __getitem__(self, key: object) -> NoReturn:
        return _unexpected_operation(key)

    def __iter__(self) -> NoReturn:
        return _unexpected_operation()

    def __len__(self) -> NoReturn:
        return _unexpected_operation()

    def get(self, key: object, default: object = None) -> NoReturn:
        return _unexpected_operation(key, default)

    def items(self) -> NoReturn:
        return _unexpected_operation()

    def keys(self) -> NoReturn:
        return _unexpected_operation()

    def values(self) -> NoReturn:
        return _unexpected_operation()

    def copy(self) -> NoReturn:
        return _unexpected_operation()

    def __contains__(self, key: object) -> NoReturn:
        return _unexpected_operation(key)


builtins.open = _unexpected_operation
os.getenv = _guarded_getenv
os.putenv = _unexpected_operation
os.unsetenv = _unexpected_operation
os.system = _unexpected_operation
os.spawnl = _unexpected_operation
os.spawnle = _unexpected_operation
os.spawnlp = _unexpected_operation
os.spawnlpe = _unexpected_operation
os.spawnv = _unexpected_operation
os.spawnve = _unexpected_operation
os.spawnvp = _unexpected_operation
os.spawnvpe = _unexpected_operation
os.startfile = _unexpected_operation
os.environ = ForbiddenEnvironment()
socket.socket = _unexpected_operation
socket.create_connection = _unexpected_operation
subprocess.Popen = _unexpected_operation
urllib.request.urlopen = _unexpected_operation
http.client.HTTPConnection.connect = _unexpected_operation
http.client.HTTPSConnection.connect = _unexpected_operation
winreg.OpenKey = _unexpected_operation
winreg.OpenKeyEx = _unexpected_operation
winreg.QueryValue = _unexpected_operation
winreg.QueryValueEx = _unexpected_operation
winreg.EnumKey = _unexpected_operation
winreg.EnumValue = _unexpected_operation
Path.cwd = _unexpected_operation
Path.home = _unexpected_operation
Path.expanduser = _unexpected_operation
Path.open = _unexpected_operation
Path.read_bytes = _unexpected_operation
Path.read_text = _unexpected_operation
Path.exists = _unexpected_operation
Path.is_dir = _unexpected_operation
Path.is_file = _unexpected_operation
Path.iterdir = _unexpected_operation
Path.glob = _unexpected_operation
Path.rglob = _unexpected_operation
Path.resolve = _unexpected_operation
Path.stat = _unexpected_operation
Path.lstat = _unexpected_operation
Path.mkdir = _unexpected_operation
Path.touch = _unexpected_operation
Path.write_bytes = _unexpected_operation
Path.write_text = _unexpected_operation

sentinel = sys.argv[1]
module_names = tuple(sys.argv[2:])
imported_names = tuple(
    importlib.import_module(module_name).__name__
    for module_name in module_names
)
if imported_names != module_names:
    raise AssertionError("imported module names did not match the requested modules")
print(sentinel)
"""


def test_all_planned_modules_import_fresh_without_observable_side_effects(
    tmp_path: Path,
) -> None:
    paths_before = tuple(tmp_path.iterdir())
    assert paths_before == ()

    repository_root = Path(__file__).resolve().parents[2]
    expected_interpreter = repository_root / ".venv" / "Scripts" / "python.exe"
    assert Path(sys.executable).resolve() == expected_interpreter.resolve()
    command: list[str] = [
        sys.executable,
        "-I",
        "-B",
        "-c",
        _IMPORT_PROBE,
        _IMPORT_SENTINEL,
        *PACKAGE_MODULES,
    ]
    completed = subprocess.run(  # noqa: S603 - fixed isolated Python command.
        command,
        cwd=tmp_path,
        check=False,
        capture_output=True,
        shell=False,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == f"{_IMPORT_SENTINEL}\n"
    assert completed.stderr == ""
    assert tuple(tmp_path.iterdir()) == paths_before


def test_distribution_metadata_reports_initial_version() -> None:
    assert version("crypto-trading-lab") == "0.1.0"


def test_package_contains_pep_561_marker() -> None:
    package = importlib.import_module("crypto_lab")
    package_file = package.__file__
    assert package_file is not None
    typing_marker = Path(package_file).with_name("py.typed")
    assert typing_marker.is_file()
    assert typing_marker.read_bytes() == b""
```

Pytest itself starts through the repository launcher, so its exact
`sys.executable` and every descendant inherit the fixed control before Python
starts. The test pins that interpreter to the repository `.venv` and starts it
directly with an argument array, avoiding any caller-selectable launcher Python
profile. The child itself imports no Pydantic package before installing guards;
its `os.getenv` guard returns the fixed literal only for the exact
`pydantic.plugin._loader` caller and rejects every application call, while its
`os.environ` mapping fails closed. Before importing any entry in
`PACKAGE_MODULES`, the child traps ambient environment/profile/registry access,
file reads and writes through the guarded APIs, network creation, and process
launch APIs. It runs in isolated mode from `tmp_path`, uses an argument array
with `shell=False`, and retains exact sentinel/stdout/stderr/filesystem
assertions. The separate launcher behavior test proves fixed child inheritance
and parent isolation. Exact source/AST review remains necessary; this bounded
guard is not claimed to intercept every possible operating-system call.

Apply the exact Task 1 patch to
`tests/safety/test_project_dependencies.py` shown in Task 1 Step 1; no
additional edit is permitted. Apply this exact Task 1 hunk to
`tests/safety/test_gitnexus_development_tooling.py`:

```diff
@@
-    assert project["dependencies"] == []
+    assert project["dependencies"] == ["pydantic>=2.12,<3"]
     assert "optional-dependencies" not in project
```

The following `tests/safety/test_stage3_boundaries.py` body is the cumulative
final file after Task 8. Task 7 creates its exact baseline using the named
omissions and seam assertions in Task 7 Step 1; Task 8 applies the exact
additive patch in Task 8 Step 1. Only after that Task 8 patch must the file equal
this body byte-for-byte:

```python
"""Enforce the Stage 3 architectural, source, schema, and verifier boundary."""

from __future__ import annotations

import ast
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from crypto_lab.schema_registry import SCHEMA_DEFINITIONS

_ALLOWED_SOURCE_FILES = {
    "__init__.py",
    "adapters/__init__.py",
    "adapters/descriptors.py",
    "adapters/versioning.py",
    "artifacts/__init__.py",
    "artifacts/ownership.py",
    "audit/__init__.py",
    "capabilities/__init__.py",
    "cli/__init__.py",
    "cli/__main__.py",
    "cli/main.py",
    "configuration/__init__.py",
    "configuration/loader.py",
    "configuration/models.py",
    "configuration/snapshot.py",
    "datasets/__init__.py",
    "datasets/hashing.py",
    "datasets/models.py",
    "domain/__init__.py",
    "domain/base.py",
    "domain/canonical_json.py",
    "domain/diagnostics.py",
    "domain/financial.py",
    "domain/hashing.py",
    "domain/identifiers.py",
    "domain/records.py",
    "domain/time.py",
    "domain/versioning.py",
    "experiments/__init__.py",
    "persistence/__init__.py",
    "process_supervision/__init__.py",
    "schema_registry.py",
    "strategy/__init__.py",
}
_ALLOWED_IMPORT_ROOTS = {
    "__future__",
    "argparse",
    "collections",
    "crypto_lab",
    "dataclasses",
    "datetime",
    "decimal",
    "enum",
    "hashlib",
    "importlib",
    "json",
    "pathlib",
    "pydantic",
    "re",
    "tomllib",
    "typing",
    "uuid",
}
_FORBIDDEN_AMBIENT_NAMES = {
    "os.environ",
    "os.getenv",
    "os.putenv",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    "os.startfile",
    "os.system",
    "os.unsetenv",
    "pathlib.Path.cwd",
    "pathlib.Path.expanduser",
    "pathlib.Path.home",
}
_DEFERRED_DEFINITIONS = {
    "AdapterCatalog",
    "AdapterCatalogEntry",
    "AdapterCommand",
    "AdapterCommandRequestEnvelope",
    "AdapterResultManifest",
    "AdapterValidationResult",
    "ApproximationDeclaration",
    "ArtifactFinalizationPurpose",
    "ArtifactFinalizer",
    "ArtifactOwnerKind",
    "ArtifactRef",
    "ArtifactRepository",
    "ArtifactSourceRole",
    "AuditSink",
    "AuditEvent",
    "BootstrapDescriptorEnvelope",
    "CancellationToken",
    "CandidateArtifact",
    "CandidateArtifactRepository",
    "CandidateArtifactState",
    "CandidateArtifactProducerKind",
    "CandidateFinalization",
    "CanonicalFill",
    "CanonicalOrder",
    "CapabilityDeclaration",
    "CapabilityRequirement",
    "CapabilityVocabulary",
    "CommandInvocationRecord",
    "CommandInvocationRepository",
    "CommandInvocationState",
    "CommandKind",
    "CommandResult",
    "ComparisonEligibilityResult",
    "ComparisonEligibilityService",
    "ComparisonLevel",
    "CompatibilityPolicy",
    "CompatibilityResolver",
    "CompatibilityOutcome",
    "CompatibilityResult",
    "ContentHasher",
    "Clock",
    "DatasetRepository",
    "EngineRunRecord",
    "EngineRunRepository",
    "EngineRunRequest",
    "EquityPoint",
    "EvidenceFinalizationRequest",
    "ExperimentRecord",
    "ExperimentRepository",
    "ExperimentSpec",
    "Fee",
    "FinalizationResult",
    "NegotiationResult",
    "MetricValue",
    "MonotonicInstant",
    "OrderSide",
    "OrderType",
    "PortfolioSnapshot",
    "PositionSnapshot",
    "PositionEffect",
    "ProcessSupervisor",
    "ProtocolEventEnvelope",
    "ResultFinalizationRequest",
    "RetryPolicy",
    "Result",
    "RunEvent",
    "RunManifest",
    "RuntimeAvailabilityObservation",
    "SanitizedAdapterResultManifest",
    "SemanticStatus",
    "StrategyLoader",
    "StrategySpec",
    "StrategyVersion",
    "UnitOfWork",
    "ValidationOutcome",
    "ingest_dataset",
    "negotiate_protocol",
    "normalize_dataset",
    "place_order",
}
_EXPECTED_VERIFICATION_PROFILES = (
    ("lock-check",),
    ("sync",),
    ("ruff-format-all",),
    ("ruff-check-all",),
    ("mypy-all",),
    ("schema-generate-check",),
    ("pytest-all",),
    ("build",),
    ("schema-distribution",),
)
_EXPECTED_VERIFIER_SHA256 = (
    "4296811ae310fc7e8e17bd3b63f4c6c794a2c6e3c8d20b642de40cf918c2c4cd"
)
_ALLOWED_VERIFIER_COMMANDS = {
    "Assert-NativeSuccess",
    "Join-Path",
    "Pop-Location",
    "Push-Location",
    "Resolve-Path",
    "Write-Host",
    "git",
    "powershell",
}


def _qualified_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value)
        return None if parent is None else f"{parent}.{node.attr}"
    return None


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.partition(".")[0]
                aliases[bound] = alias.name if alias.asname else bound
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            for alias in node.names:
                if alias.name == "*":
                    continue
                bound = alias.asname or alias.name
                aliases[bound] = f"{node.module}.{alias.name}"
    return aliases


def _resolved_qualified_name(
    node: ast.AST,
    aliases: dict[str, str],
) -> str | None:
    name = _qualified_name(node)
    if name is None:
        return None
    head, separator, tail = name.partition(".")
    resolved = aliases.get(head, head)
    return resolved if not separator else f"{resolved}.{tail}"


def _source_files(repository_root: Path) -> tuple[Path, ...]:
    return tuple(sorted((repository_root / "src/crypto_lab").rglob("*.py")))


def _normalized_source(path: Path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    return "\n".join(line.rstrip() for line in lines) + "\n"


def _powershell() -> str:
    executable = shutil.which("powershell")
    assert executable is not None
    return executable


def _powershell_command_records(
    path: Path,
    repository_root: Path,
) -> tuple[dict[str, str], ...]:
    parser = (
        "$path=[Console]::In.ReadLine();$tokens=$null;$errors=$null;"
        "$ast=[System.Management.Automation.Language.Parser]::ParseFile("
        "$path,[ref]$tokens,[ref]$errors);"
        "if($errors.Count-ne 0){exit 91};"
        "$records=@($ast.FindAll({param($node) $node -is "
        "[System.Management.Automation.Language.CommandAst]},$true)|"
        "ForEach-Object{$name=$_.GetCommandName();"
        "if($null-eq$name){$name='<dynamic>'};"
        "[pscustomobject]@{name=$name;text=$_.Extent.Text}});"
        "$records|ConvertTo-Json -Compress"
    )
    completed = subprocess.run(  # noqa: S603 - reviewed fixed parser boundary
        [_powershell(), "-NoProfile", "-Command", parser],
        cwd=repository_root,
        input=f"{path}\n",
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
    )
    assert completed.returncode == 0, completed.stderr
    decoded = json.loads(completed.stdout)
    records = [decoded] if isinstance(decoded, dict) else decoded
    assert isinstance(records, list)
    assert all(isinstance(record, dict) for record in records)
    return tuple(records)


def _normalized_extent(text: str) -> str:
    return " ".join(text.replace("`", "").split())


def _verifier_profiles(
    records: tuple[dict[str, str], ...],
) -> tuple[tuple[str, ...], ...]:
    profiles: list[tuple[str, ...]] = []
    for record in records:
        if record["name"].casefold() != "powershell":
            continue
        tokens = _normalized_extent(record["text"]).split()
        launcher_index = next(
            index
            for index, token in enumerate(tokens)
            if token.casefold().endswith("scripts\\invoke-uv.ps1")
        )
        profiles.append(tuple(tokens[launcher_index + 1 :]))
    return tuple(profiles)


def _verifier_is_exactly_closed(path: Path, repository_root: Path) -> bool:
    digest = hashlib.sha256(_normalized_source(path).encode()).hexdigest()
    records = _powershell_command_records(path, repository_root)
    commands = {record["name"] for record in records}
    return (
        digest == _EXPECTED_VERIFIER_SHA256
        and commands == _ALLOWED_VERIFIER_COMMANDS
        and _verifier_profiles(records) == _EXPECTED_VERIFICATION_PROFILES
        and tuple(
            _normalized_extent(record["text"])
            for record in records
            if record["name"].casefold() == "git"
        )
        == ("& git diff --check",)
    )


def test_stage3_source_file_set_is_closed(repository_root: Path) -> None:
    source = repository_root / "src/crypto_lab"
    actual = {
        path.relative_to(source).as_posix() for path in _source_files(repository_root)
    }
    assert actual == _ALLOWED_SOURCE_FILES


def test_source_imports_only_the_explicit_stage3_allowlist(
    repository_root: Path,
) -> None:
    failures: list[str] = []
    for path in _source_files(repository_root):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                modules.append(node.module)
            for module in modules:
                root = module.partition(".")[0]
                if root not in _ALLOWED_IMPORT_ROOTS:
                    failures.append(f"{path}: import root is not allowed: {module}")
    assert failures == []


def test_source_has_no_ambient_access_or_later_stage_definitions(
    repository_root: Path,
) -> None:
    failures: list[str] = []
    for path in _source_files(repository_root):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        aliases = _import_aliases(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Name | ast.Attribute):
                name = _resolved_qualified_name(node, aliases)
                if name in _FORBIDDEN_AMBIENT_NAMES:
                    failures.append(f"{path}: forbidden ambient access {name}")
            if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
                if node.name in _DEFERRED_DEFINITIONS:
                    failures.append(f"{path}: later-stage definition {node.name}")
    assert failures == []


def test_alias_resolution_cannot_hide_ambient_access() -> None:
    tree = ast.parse(
        "import os as operating\n"
        "from pathlib import Path as LocalPath\n"
        "operating.getenv('name')\n"
        "LocalPath.home()\n"
    )
    aliases = _import_aliases(tree)
    resolved = {
        name
        for node in ast.walk(tree)
        if isinstance(node, ast.Name | ast.Attribute)
        and (name := _resolved_qualified_name(node, aliases)) is not None
    }
    assert "os.getenv" in resolved
    assert "pathlib.Path.home" in resolved


@pytest.mark.parametrize("name", sorted(_DEFERRED_DEFINITIONS))
def test_each_normative_deferred_symbol_is_detected_by_the_stage3_guard(
    name: str,
) -> None:
    keyword = "class" if name[0].isupper() else "def"
    tree = ast.parse(
        f"{keyword} {name}:\n    pass\n"
        if keyword == "class"
        else f"def {name}():\n    pass\n"
    )
    defined = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
    }
    assert defined & _DEFERRED_DEFINITIONS == {name}


@pytest.mark.parametrize(
    "name",
    [
        "AdapterResultManifest",
        "CandidateArtifactState",
        "CanonicalOrder",
        "CommandInvocationState",
        "EngineRunRequest",
        "PortfolioSnapshot",
        "ValidationOutcome",
    ],
)
def test_representative_later_stage_type_mutations_are_blocked(name: str) -> None:
    tree = ast.parse(f"class {name}:\n    pass\n")
    later = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
        and node.name in _DEFERRED_DEFINITIONS
    }
    assert later == {name}


def test_schema_registry_is_closed_and_protocol_descriptors_are_located_correctly() -> (
    None
):
    paths = tuple(
        definition.relative_path.as_posix() for definition in SCHEMA_DEFINITIONS
    )
    identifiers = tuple(definition.schema_id for definition in SCHEMA_DEFINITIONS)
    assert len(paths) == 11
    assert len(paths) == len(set(paths))
    assert len(identifiers) == len(set(identifiers))
    assert "protocol/engine-descriptor-v1.schema.json" in paths
    assert "protocol/adapter-descriptor-v1.schema.json" in paths
    assert all(not path.startswith("adapters/") for path in paths)
    assert all("semantic-version" not in path for path in paths)


def test_complete_verifier_has_exact_offline_order(repository_root: Path) -> None:
    verifier = repository_root / "scripts" / "verify.ps1"
    assert _verifier_is_exactly_closed(verifier, repository_root)


@pytest.mark.parametrize(
    ("injected", "expected_ast_name"),
    [
        (
            "bitsadmin /transfer bad https://example.invalid out",
            "bitsadmin",
        ),
        (
            "certutil -urlcache -split -f https://example.invalid out",
            "certutil",
        ),
        ("[System.Net.Http.HttpClient]::new()", None),
        ("$executable = 'uv'; & $executable --version", "<dynamic>"),
    ],
)
def test_verifier_mutations_fail_exact_hash_and_ast_closure(
    repository_root: Path,
    tmp_path: Path,
    injected: str,
    expected_ast_name: str | None,
) -> None:
    source = _normalized_source(repository_root / "scripts" / "verify.ps1")
    mutated = tmp_path / "mutated-verifier.ps1"
    mutated.write_text(f"{source}{injected}\n", encoding="utf-8")
    assert not _verifier_is_exactly_closed(mutated, repository_root)
    if expected_ast_name is not None:
        records = _powershell_command_records(mutated, repository_root)
        assert expected_ast_name in {record["name"] for record in records}


def test_gitnexus_remains_disabled_with_evidence(repository_root: Path) -> None:
    outcome = (repository_root / "tools/gitnexus/outcome.json").read_text(
        encoding="utf-8"
    )
    assert '"outcome": "DISABLED_WITH_EVIDENCE"' in outcome
```

The source scan is intentionally bounded: it proves that the Stage 3 modules
contain none of the named ambient, networking, or process primitives. Together
with the isolated import test and exact review, it is not represented as a
proof against every possible operating-system side effect.

In Task 9, append this exact test to
`tests/safety/test_stage3_boundaries.py` after substituting the captured
40-character implementation commit for `STAGE3_IMPLEMENTATION_COMMIT` in both
the Python constant and roadmap row:

First add the required standard-library import:

```diff
 import json
+import re
 import shutil
```

```python
STAGE3_IMPLEMENTATION_COMMIT = "__STAGE3_IMPLEMENTATION_COMMIT__"


def test_stage3_completion_status_is_exact(repository_root: Path) -> None:
    assert re.fullmatch(r"[0-9a-f]{40}", STAGE3_IMPLEMENTATION_COMMIT) is not None
    roadmap = (
        repository_root
        / "docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md"
    ).read_text(encoding="utf-8")
    readme = (repository_root / "README.md").read_text(encoding="utf-8")
    assert "Stages 1 through 3 complete" in roadmap
    assert "Stages 1 through 3 have approved detailed implementation plans." in roadmap
    assert (
        "| 3 — Canonical Domain, Configuration, Hashing, and Schemas | "
        "Approved and executed | Complete at "
        f"`{STAGE3_IMPLEMENTATION_COMMIT}` | Complete; canonical models, "
        "explicit configuration, named hashes, dataset metadata, structural "
        "descriptors, artifact owners, and 11 generated schemas verified offline |"
    ) in roadmap
    assert "Eligible for just-in-time planning after Stage 3 completion" in roadmap
    assert "`DISABLED_WITH_EVIDENCE`" in roadmap
    assert "**Status:** Project 1 Stages 1-3 complete" in readme
```

`__STAGE3_IMPLEMENTATION_COMMIT__` is a mandatory runtime binding token, not
an undecided value: Step 2 captures it after the complete implementation
verification/review loop and before any status edit, Step 4 binds it
in both the test constant and roadmap row, and the regex deliberately fails if
the binding is omitted.

In the existing roadmap-status test in
`tests/safety/test_gitnexus_development_tooling.py`, apply this exact Task 9
patch:

```diff
@@
-    assert "Stages 1 and 2 have approved detailed implementation plans." in roadmap
+    assert "Stages 1 through 3 have approved detailed implementation plans." in roadmap
@@
-        "**Status:** Approved planning decomposition; Stages 1 and 2 complete"
+        "**Status:** Approved planning decomposition; Stages 1 through 3 complete"
```

Do not alter the Stage 2 outcome branches, exact disabled row, optional-tooling
assertions, or absence checks.

---

### A.9 Exact domain test files

Create `tests/unit/domain/test_identifiers.py` with exactly:

```python
from __future__ import annotations

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import TypeAdapter, ValidationError

from crypto_lab.domain.identifiers import (
    ArtifactId,
    AssetCode,
    AuditEventId,
    CandidateArtifactId,
    DatasetId,
    DatasetPartitionId,
    DiagnosticId,
    EventId,
    ExperimentId,
    InvocationId,
    NormalizedIdentifier,
    RunId,
    Sha256,
    StrategyId,
    StrategyVersionId,
)

_UUID4 = "12345678-1234-4234-8234-123456789abc"
_ID_CASES: list[tuple[TypeAdapter[str], str]] = [
    (TypeAdapter(ExperimentId), "exp_"),
    (TypeAdapter(RunId), "run_"),
    (TypeAdapter(ArtifactId), "art_"),
    (TypeAdapter(DatasetId), "ds_"),
    (TypeAdapter(StrategyId), "strat_"),
    (TypeAdapter(StrategyVersionId), "strv_"),
    (TypeAdapter(InvocationId), "inv_"),
    (TypeAdapter(EventId), "evt_"),
    (TypeAdapter(CandidateArtifactId), "cand_"),
    (TypeAdapter(DiagnosticId), "diag_"),
    (TypeAdapter(AuditEventId), "audit_"),
    (TypeAdapter(DatasetPartitionId), "part_"),
]


@pytest.mark.parametrize(("adapter", "prefix"), _ID_CASES)
def test_prefixed_uuid4_alias_accepts_only_its_canonical_family(
    adapter: TypeAdapter[str],
    prefix: str,
) -> None:
    value = f"{prefix}{_UUID4}"
    assert adapter.validate_python(value) == value
    for invalid in (
        f"wrong_{_UUID4}",
        f"{prefix}12345678-1234-1234-8234-123456789abc",
        f"{prefix}00000000-0000-0000-0000-000000000000",
        f"{prefix}{_UUID4.upper()}",
        f"{prefix}{{{_UUID4}}}",
        _UUID4,
        f" {value}",
        f"{value} ",
    ):
        with pytest.raises(ValidationError):
            adapter.validate_python(invalid)


@pytest.mark.parametrize(
    ("adapter", "valid", "invalid"),
    [
        (
            TypeAdapter(Sha256),
            "a" * 64,
            ("A" * 64, "a" * 63, "g" * 64, " " + "a" * 64),
        ),
        (
            TypeAdapter(NormalizedIdentifier),
            "schema.registry-v1",
            ("Schema", "two words", "", "_leading", "trailing_"),
        ),
        (
            TypeAdapter(AssetCode),
            "BTC.USDT-V1",
            ("btc", "two words", "", "_BTC", "BTC!"),
        ),
    ],
)
def test_constrained_string_aliases(
    adapter: TypeAdapter[str],
    valid: str,
    invalid: tuple[str, ...],
) -> None:
    assert adapter.validate_python(valid) == valid
    for value in invalid:
        with pytest.raises(ValidationError):
            adapter.validate_python(value)
    with pytest.raises(ValidationError):
        adapter.validate_python(1)


@pytest.mark.parametrize(
    ("adapter", "valid"),
    [
        *((adapter, f"{prefix}{_UUID4}") for adapter, prefix in _ID_CASES),
        (TypeAdapter(Sha256), "a" * 64),
        (TypeAdapter(NormalizedIdentifier), "schema.registry-v1"),
        (TypeAdapter(AssetCode), "BTC.USDT-V1"),
    ],
)
def test_identifier_schemas_reject_terminal_newline(
    adapter: TypeAdapter[str],
    valid: str,
) -> None:
    schemas = (
        adapter.json_schema(mode="validation"),
        adapter.json_schema(mode="serialization"),
    )
    for schema in schemas:
        assert schema["pattern"].endswith(r"(?![\s\S])")
        validator = Draft202012Validator(schema)
        validator.validate(valid)
        for terminator in ("\n", "\r", "\r\n"):
            with pytest.raises(ValidationError):
                adapter.validate_python(valid + terminator)
            with pytest.raises(JsonSchemaValidationError):
                validator.validate(valid + terminator)
```

Create `tests/unit/domain/test_time.py` with exactly:

```python
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import TypeAdapter, ValidationError

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.time import UtcDateTime, format_utc


class UtcProbe(CanonicalModel):
    value: UtcDateTime


def test_utc_python_and_json_round_trip_are_canonical() -> None:
    seconds = UtcProbe(value=datetime(2026, 8, 10, 1, 2, 3, tzinfo=UTC))
    micros = UtcProbe(value=datetime(2026, 8, 10, 1, 2, 3, 42, tzinfo=UTC))
    assert seconds.model_dump_json() == '{"value":"2026-08-10T01:02:03Z"}'
    assert micros.model_dump_json() == ('{"value":"2026-08-10T01:02:03.000042Z"}')
    assert UtcProbe.model_validate_json(seconds.model_dump_json()) == seconds
    assert format_utc(seconds.value) == "2026-08-10T01:02:03Z"


@pytest.mark.parametrize(
    "value",
    [
        datetime(2026, 8, 10, 1, 2, 3),  # noqa: DTZ001 - deliberate rejection case
        datetime(
            2026,
            8,
            10,
            1,
            2,
            3,
            tzinfo=timezone(timedelta(hours=5, minutes=30)),
        ),
        "2026-08-10T01:02:03Z",
    ],
)
def test_python_validation_rejects_non_typed_or_non_utc_values(
    value: object,
) -> None:
    with pytest.raises(ValidationError):
        UtcProbe.model_validate({"value": value})


@pytest.mark.parametrize(
    "value",
    [
        datetime(2026, 8, 10, 1, 2, 3),  # noqa: DTZ001 - rejection case
        datetime(
            2026,
            8,
            10,
            1,
            2,
            3,
            tzinfo=timezone(timedelta(hours=1)),
        ),
    ],
)
def test_format_utc_rejects_naive_and_nonzero_offset_values(value: datetime) -> None:
    with pytest.raises(ValueError, match="UTC"):
        format_utc(value)


@pytest.mark.parametrize(
    "document",
    [
        '{"value":"2026-02-30T01:02:03Z"}',
        '{"value":"2026-08-10T01:02:03+00:00"}',
        '{"value":"2026-08-10T01:02:03.1Z"}',
    ],
)
def test_json_validation_rejects_noncanonical_utc_text(document: str) -> None:
    with pytest.raises(ValidationError):
        UtcProbe.model_validate_json(document)


def test_utc_schema_requires_the_exact_z_form() -> None:
    adapter = TypeAdapter(UtcDateTime)
    schemas = (
        adapter.json_schema(mode="validation"),
        adapter.json_schema(mode="serialization"),
    )
    for schema in schemas:
        assert schema["type"] == "string"
        assert schema["format"] == "date-time"
        assert schema["pattern"].endswith(r"Z(?![\s\S])")
        validator = Draft202012Validator(schema)
        validator.validate("2026-08-10T01:02:03Z")
        for terminator in ("\n", "\r", "\r\n"):
            with pytest.raises(ValidationError):
                adapter.validate_json(json.dumps("2026-08-10T01:02:03Z" + terminator))
            with pytest.raises(JsonSchemaValidationError):
                validator.validate("2026-08-10T01:02:03Z" + terminator)
```

Create `tests/unit/domain/test_financial.py` with exactly:

```python
from __future__ import annotations

import json
from decimal import Decimal, localcontext

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import TypeAdapter, ValidationError

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.financial import (
    CanonicalDecimal,
    NonNegativeDecimal,
    PositiveDecimal,
    format_decimal,
)


class DecimalProbe(CanonicalModel):
    value: CanonicalDecimal


class PositiveProbe(CanonicalModel):
    value: PositiveDecimal


class NonNegativeProbe(CanonicalModel):
    value: NonNegativeDecimal


_DECIMAL_ADAPTERS: list[TypeAdapter[Decimal]] = [
    TypeAdapter(CanonicalDecimal),
    TypeAdapter(PositiveDecimal),
    TypeAdapter(NonNegativeDecimal),
]


@pytest.mark.parametrize(
    ("value", "encoded"),
    [
        (Decimal("0"), '{"value":"0"}'),
        (Decimal("1E+3"), '{"value":"1000"}'),
        (Decimal("1.2300"), '{"value":"1.23"}'),
        (Decimal("-0.00100"), '{"value":"-0.001"}'),
    ],
)
def test_typed_decimal_serializes_as_canonical_fixed_point(
    value: Decimal,
    encoded: str,
) -> None:
    model = DecimalProbe(value=value)
    assert model.model_dump_json() == encoded
    assert DecimalProbe.model_validate_json(encoded) == model


@pytest.mark.parametrize("value", [0, 1, 1.0, True, "1.23", None])
def test_python_mode_rejects_every_non_decimal(value: object) -> None:
    with pytest.raises((TypeError, ValidationError)):
        DecimalProbe.model_validate({"value": value})


@pytest.mark.parametrize(
    "document",
    [
        '{"value":1.23}',
        '{"value":"1E+3"}',
        '{"value":"1.2300"}',
        '{"value":"1.0"}',
        '{"value":"+1"}',
        '{"value":"01"}',
        '{"value":"-0"}',
        '{"value":"-0.0"}',
        '{"value":"NaN"}',
        '{"value":"Infinity"}',
        '{"value":""}',
        '{"value":" 1"}',
    ],
)
def test_json_mode_rejects_noncanonical_decimal_forms(document: str) -> None:
    with pytest.raises((TypeError, ValidationError)):
        DecimalProbe.model_validate_json(document)


@pytest.mark.parametrize(
    "value",
    [Decimal("-0"), Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")],
)
def test_typed_decimal_rejects_noncanonical_special_values(
    value: Decimal,
) -> None:
    with pytest.raises(ValidationError):
        DecimalProbe(value=value)


def test_sign_constrained_aliases() -> None:
    assert PositiveProbe(value=Decimal("0.1")).value == Decimal("0.1")
    assert NonNegativeProbe(value=Decimal("0")).value == Decimal("0")
    with pytest.raises(ValidationError):
        PositiveProbe(value=Decimal("0"))
    with pytest.raises(ValidationError):
        NonNegativeProbe(value=Decimal("-0.1"))


def test_formatting_is_independent_of_decimal_context() -> None:
    with localcontext() as context:
        context.prec = 2
        assert format_decimal(Decimal("123456789.1234500")) == "123456789.12345"


def test_extreme_exponent_is_rejected_before_render_allocation() -> None:
    with pytest.raises(ValidationError, match="maximum length"):
        DecimalProbe(value=Decimal("1E+100000000"))


@pytest.mark.parametrize("adapter", _DECIMAL_ADAPTERS)
def test_decimal_json_schemas_are_string_only(
    adapter: TypeAdapter[Decimal],
) -> None:
    schemas = (
        adapter.json_schema(mode="validation"),
        adapter.json_schema(mode="serialization"),
    )
    for schema in schemas:
        assert schema["type"] == "string"
        assert schema["pattern"].endswith(r"(?![\s\S])")
        assert "maxLength" in schema
        validator = Draft202012Validator(schema)
        validator.validate("1")
        for terminator in ("\n", "\r", "\r\n"):
            with pytest.raises(ValidationError):
                adapter.validate_json(json.dumps("1" + terminator))
            with pytest.raises(JsonSchemaValidationError):
                validator.validate("1" + terminator)
```

Create `tests/unit/domain/test_records.py` with exactly:

```python
from __future__ import annotations

from decimal import Decimal

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import TypeAdapter, ValidationError

from crypto_lab.domain.records import (
    InstrumentId,
    InstrumentRef,
    MarketType,
    Money,
    Price,
    Quantity,
    parse_instrument_id,
)

_INSTRUMENT = "BINANCE:BTC/USDT:SPOT"


def _instrument() -> InstrumentRef:
    return InstrumentRef(
        schema_version="1.0.0",
        canonical_id=_INSTRUMENT,
        venue="BINANCE",
        base_asset="BTC",
        quote_asset="USDT",
        market_type=MarketType.SPOT,
    )


def test_instrument_id_is_a_strict_canonical_boundary() -> None:
    adapter = TypeAdapter(InstrumentId)
    assert adapter.validate_python(_INSTRUMENT) == _INSTRUMENT
    for invalid in (
        "BINANCE:BTC-USDT:SPOT",
        "BINANCE:BTC/USDT:UNKNOWN",
        "BINANCE::BTC/USDT:SPOT",
        "BINANCE:BTC//USDT:SPOT",
        "binance:BTC/USDT:SPOT",
        "BINANCE:_BTC/USDT:SPOT",
    ):
        with pytest.raises(ValidationError):
            adapter.validate_python(invalid)
    with pytest.raises(ValidationError):
        adapter.validate_python(1)


@pytest.mark.parametrize(
    ("valid", "invalid"),
    [
        (
            f"{'A' * 32}:BTC/USDT:SPOT",
            f"{'A' * 33}:BTC/USDT:SPOT",
        ),
        (
            f"BINANCE:{'A' * 32}/USDT:SPOT",
            f"BINANCE:{'A' * 33}/USDT:SPOT",
        ),
        (
            f"BINANCE:BTC/{'A' * 32}:SPOT",
            f"BINANCE:BTC/{'A' * 33}:SPOT",
        ),
    ],
)
def test_instrument_id_enforces_each_component_length(
    valid: str,
    invalid: str,
) -> None:
    adapter = TypeAdapter(InstrumentId)
    assert adapter.validate_python(valid) == valid
    with pytest.raises(ValidationError, match="32 characters"):
        adapter.validate_python(invalid)


def test_instrument_id_json_schemas_enforce_component_bounds() -> None:
    adapter = TypeAdapter(InstrumentId)
    schemas = (
        adapter.json_schema(mode="validation"),
        adapter.json_schema(mode="serialization"),
    )
    invalid = [
        "BINANCE:BTC-USDT:SPOT",
        "BINANCE:BTC/USDT:UNKNOWN",
        "BINANCE::BTC/USDT:SPOT",
        "BINANCE:BTC//USDT:SPOT",
        "binance:BTC/USDT:SPOT",
        "BINANCE:_BTC/USDT:SPOT",
        f"{'A' * 33}:BTC/USDT:SPOT",
        f"BINANCE:{'A' * 33}/USDT:SPOT",
        f"BINANCE:BTC/{'A' * 33}:SPOT",
    ]
    invalid.extend(_INSTRUMENT + terminator for terminator in ("\n", "\r", "\r\n"))
    for schema in schemas:
        assert schema["type"] == "string"
        assert schema["minLength"] == 10
        assert schema["maxLength"] == 107
        assert len(schema["allOf"]) == 2
        patterns = [branch["pattern"] for branch in schema["allOf"]]
        assert all("(?P<" not in pattern for pattern in patterns)
        assert all("(?=" not in pattern for pattern in patterns)
        validator = Draft202012Validator(schema)
        validator.validate(_INSTRUMENT)
        for value in invalid:
            with pytest.raises(ValidationError):
                adapter.validate_python(value)
            with pytest.raises(JsonSchemaValidationError):
                validator.validate(value)


def test_instrument_ref_reconstructs_exact_identity() -> None:
    instrument = _instrument()
    assert parse_instrument_id(instrument.canonical_id) == (
        "BINANCE",
        "BTC",
        "USDT",
        "SPOT",
    )
    assert InstrumentRef.model_validate_json(instrument.model_dump_json()) == instrument


@pytest.mark.parametrize(
    "update",
    [
        {"canonical_id": "BINANCE:ETH/USDT:SPOT"},
        {"canonical_id": "BINANCE:BTC-USDT:SPOT"},
        {"market_type": "UNKNOWN"},
    ],
)
def test_instrument_ref_rejects_inconsistent_or_foreign_fields(
    update: dict[str, object],
) -> None:
    payload = _instrument().model_dump(mode="python")
    payload.update(update)
    with pytest.raises(ValidationError):
        InstrumentRef.model_validate(payload)


def test_instrument_ref_rejects_same_base_and_quote() -> None:
    payload = _instrument().model_dump(mode="python")
    payload.update(
        {
            "canonical_id": "BINANCE:BTC/BTC:SPOT",
            "quote_asset": "BTC",
        }
    )
    with pytest.raises(
        ValidationError,
        match="base_asset and quote_asset must differ",
    ):
        InstrumentRef.model_validate(payload)


def test_instrument_ref_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        InstrumentRef.model_validate(
            {
                **_instrument().model_dump(mode="python"),
                "unexpected": "rejected",
            }
        )


def test_money_price_and_quantity_round_trip() -> None:
    money = Money(
        schema_version="1.0.0",
        currency="USDT",
        amount=Decimal("-1.25"),
    )
    price = Price(
        schema_version="1.0.0",
        instrument_id=_INSTRUMENT,
        quote_asset="USDT",
        value=Decimal("65000.25"),
    )
    quantity = Quantity(
        schema_version="1.0.0",
        instrument_id=_INSTRUMENT,
        base_asset="BTC",
        value=Decimal("0"),
    )
    assert Money.model_validate_json(money.model_dump_json()) == money
    assert Price.model_validate_json(price.model_dump_json()) == price
    assert Quantity.model_validate_json(quantity.model_dump_json()) == quantity


@pytest.mark.parametrize(
    ("model_type", "payload"),
    [
        (
            Money,
            {"schema_version": "1.0.0", "currency": "USDT", "amount": 1.0},
        ),
        (
            Price,
            {
                "schema_version": "1.0.0",
                "instrument_id": _INSTRUMENT,
                "quote_asset": "USDT",
                "value": Decimal("0"),
            },
        ),
        (
            Price,
            {
                "schema_version": "1.0.0",
                "instrument_id": _INSTRUMENT,
                "quote_asset": "USDT",
                "value": Decimal("-1"),
            },
        ),
        (
            Price,
            {
                "schema_version": "1.0.0",
                "instrument_id": _INSTRUMENT,
                "quote_asset": "BTC",
                "value": Decimal("1"),
            },
        ),
        (
            Quantity,
            {
                "schema_version": "1.0.0",
                "instrument_id": _INSTRUMENT,
                "base_asset": "BTC",
                "value": Decimal("-0.1"),
            },
        ),
        (
            Quantity,
            {
                "schema_version": "1.0.0",
                "instrument_id": _INSTRUMENT,
                "base_asset": "USDT",
                "value": Decimal("1"),
            },
        ),
    ],
)
def test_financial_records_reject_invalid_values(
    model_type: type[Money] | type[Price] | type[Quantity],
    payload: dict[str, object],
) -> None:
    with pytest.raises((TypeError, ValidationError)):
        model_type.model_validate(payload)


def test_money_rejects_noncanonical_json_decimal_string() -> None:
    with pytest.raises(ValidationError):
        Money.model_validate_json(
            '{"schema_version":"1.0.0","currency":"USDT","amount":"1.0"}'
        )


@pytest.mark.parametrize("model_type", [Price, Quantity])
def test_instrument_linked_records_reject_malformed_instrument_id(
    model_type: type[Price] | type[Quantity],
) -> None:
    payload = {
        "schema_version": "1.0.0",
        "instrument_id": "BINANCE:BTC-USDT:SPOT",
        "value": Decimal("1"),
    }
    if model_type is Price:
        payload["quote_asset"] = "USDT"
    else:
        payload["base_asset"] = "BTC"
    with pytest.raises(ValidationError):
        model_type.model_validate(payload)


@pytest.mark.parametrize(
    "model",
    [
        Money(schema_version="1.0.0", currency="USDT", amount=Decimal("1")),
        Price(
            schema_version="1.0.0",
            instrument_id=_INSTRUMENT,
            quote_asset="USDT",
            value=Decimal("1"),
        ),
        Quantity(
            schema_version="1.0.0",
            instrument_id=_INSTRUMENT,
            base_asset="BTC",
            value=Decimal("1"),
        ),
    ],
)
def test_financial_records_reject_unknown_fields(
    model: Money | Price | Quantity,
) -> None:
    payload = model.model_dump(mode="python")
    payload["unexpected"] = "rejected"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        type(model).model_validate(payload)
```

Create `tests/unit/domain/test_canonical_json.py` with exactly:

```python
from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from enum import IntEnum, StrEnum

import pytest

from crypto_lab.domain.canonical_json import (
    canonical_json_bytes,
    canonical_json_text,
)


class ExampleEnum(StrEnum):
    VALUE = "VALUE"


class IntegerEnum(IntEnum):
    VALUE = 1


class StringSubclass(str):
    pass


def test_canonical_json_matches_the_golden_byte_profile() -> None:
    value = {
        "z": [True, 2, "é"],
        "a": Decimal("1.2300"),
        "enum": ExampleEnum.VALUE,
        "nested": {"time": datetime(2026, 8, 10, 1, 2, 3, tzinfo=UTC)},
    }
    expected = (
        '{"a":"1.23","enum":"VALUE","nested":'
        '{"time":"2026-08-10T01:02:03Z"},"z":[true,2,"é"]}'
    )
    assert canonical_json_text(value) == expected
    assert canonical_json_bytes(value) == expected.encode("utf-8")


def test_object_key_order_is_irrelevant_and_array_order_is_material() -> None:
    left = {"b": {"d": 2, "c": 1}, "a": [1, 2]}
    right = {"a": [1, 2], "b": {"c": 1, "d": 2}}
    assert canonical_json_bytes(left) == canonical_json_bytes(right)
    assert canonical_json_bytes({"a": [1, 2]}) != canonical_json_bytes({"a": [2, 1]})


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (1.0, "float is forbidden"),
        (b"bytes", "unsupported canonical JSON type"),
        ({1, 2}, "unsupported canonical JSON type"),
        (object(), "unsupported canonical JSON type"),
        (IntegerEnum.VALUE, "unsupported canonical JSON type"),
        ({1: "non-string-key"}, "keys must be strings"),
        ({StringSubclass("key"): "subclass-key"}, "keys must be strings"),
        ({ExampleEnum.VALUE: "enum-key"}, "keys must be strings"),
        (
            datetime(2026, 8, 10, 1, 2, 3),  # noqa: DTZ001 - rejection case
            "timezone-aware UTC",
        ),
        (
            datetime(
                2026,
                8,
                10,
                1,
                2,
                3,
                tzinfo=timezone(timedelta(hours=1)),
            ),
            "offset must be UTC",
        ),
    ],
)
def test_unsupported_values_are_rejected_before_json_coercion(
    value: object,
    message: str,
) -> None:
    with pytest.raises((TypeError, ValueError), match=message):
        canonical_json_bytes(value)


def test_cycles_are_rejected() -> None:
    cyclic: list[object] = []
    cyclic.append(cyclic)
    with pytest.raises(ValueError, match="cyclic canonical value"):
        canonical_json_bytes(cyclic)
```

Create `tests/unit/domain/test_hashing.py` with exactly:

```python
from __future__ import annotations

from typing import cast

import pytest
from pydantic import JsonValue

from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.hashing import (
    CanonicalHashEnvelope,
    HashingProfile,
    attempt_token_hash,
    profile_hash,
    sha256_bytes,
)

_ATTEMPT_GOLDEN = "c2e83ef7cf00c619f6cfb843bcfffbb91da6ae7b26de5110f36db68762ec74de"
_OWNER_GOLDEN = "1ec94f41e62924c7715e7a6cd4c34cfa05af92060ecd7f05b8ebba580d213b11"


def test_sha256_and_attempt_token_goldens() -> None:
    assert sha256_bytes(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert attempt_token_hash("token-123") == _ATTEMPT_GOLDEN


@pytest.mark.parametrize("token", ["", "x" * 1025])
def test_attempt_token_length_is_bounded(token: str) -> None:
    with pytest.raises(ValueError, match="length must be 1 through 1024"):
        attempt_token_hash(token)


class TokenSubclass(str):
    pass


@pytest.mark.parametrize("token", [b"bytes", 1, TokenSubclass("token")])
def test_attempt_token_requires_an_exact_builtin_string(token: object) -> None:
    with pytest.raises(TypeError, match="must be a built-in string"):
        attempt_token_hash(cast(str, token))


def test_system_owner_envelope_matches_golden_bytes_and_hash() -> None:
    payload: dict[str, JsonValue] = {
        "owner_kind": "SYSTEM",
        "core_component": "schema_registry",
        "correlation_id": "stage3",
    }
    envelope = CanonicalHashEnvelope(
        schema_version="1.0.0",
        hashing_profile=HashingProfile.ARTIFACT_OWNER_V1,
        payload=payload,
    )
    expected = (
        b'{"hashing_profile":"artifact-owner/v1","payload":'
        b'{"core_component":"schema_registry","correlation_id":"stage3",'
        b'"owner_kind":"SYSTEM"},"schema_version":"1.0.0"}'
    )
    assert canonical_json_bytes(envelope) == expected
    assert profile_hash(HashingProfile.ARTIFACT_OWNER_V1, payload) == _OWNER_GOLDEN


def test_profile_name_is_part_of_the_hash_domain() -> None:
    payload: dict[str, JsonValue] = {"value": "same"}
    hashes = {profile_hash(profile, payload) for profile in HashingProfile}
    assert len(hashes) == len(HashingProfile)
```

Create `tests/property/test_canonical_primitives.py` with exactly:

```python
from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from typing import cast
from uuid import UUID

from hypothesis import given
from hypothesis import strategies as st
from pydantic import TypeAdapter

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.financial import CanonicalDecimal
from crypto_lab.domain.identifiers import ExperimentId
from crypto_lab.domain.time import UtcDateTime


class DecimalProbe(CanonicalModel):
    value: CanonicalDecimal


class UtcProbe(CanonicalModel):
    value: UtcDateTime


@given(
    st.decimals(
        min_value=Decimal("-1000000000000"),
        max_value=Decimal("1000000000000"),
        allow_nan=False,
        allow_infinity=False,
        places=12,
    ).filter(lambda value: not (value.is_zero() and value.is_signed()))
)
def test_decimal_json_round_trip_is_canonical(value: Decimal) -> None:
    model = DecimalProbe(value=value)
    encoded = model.model_dump_json()
    payload = cast(dict[str, str], json.loads(encoded))
    assert DecimalProbe.model_validate_json(encoded) == model
    assert "e" not in payload["value"].casefold()


@given(
    st.datetimes(
        min_value=datetime(2000, 1, 1),  # noqa: DTZ001 - Hypothesis requires naive bounds
        max_value=datetime(2100, 1, 1),  # noqa: DTZ001 - Hypothesis requires naive bounds
        timezones=st.just(UTC),
    )
)
def test_utc_json_round_trip_ends_in_z(value: datetime) -> None:
    model = UtcProbe(value=value)
    encoded = model.model_dump_json()
    assert encoded.endswith('Z"}')
    assert UtcProbe.model_validate_json(encoded) == model


@given(st.uuids(version=4))
def test_generated_uuid4_accepts_only_the_matching_prefix(value: UUID) -> None:
    identifier = f"exp_{value}"
    assert TypeAdapter(ExperimentId).validate_python(identifier) == identifier
```

Task 3 applies this exact patch to the Task 2 property file:

```diff
@@
 from crypto_lab.domain.base import CanonicalModel
+from crypto_lab.domain.canonical_json import canonical_json_bytes
 from crypto_lab.domain.financial import CanonicalDecimal
@@
+
+
+@given(
+    st.dictionaries(
+        st.text(min_size=1, max_size=8),
+        st.integers(),
+        max_size=8,
+    )
+)
+def test_canonical_object_is_key_order_invariant(value: dict[str, int]) -> None:
+    reversed_value = dict(reversed(tuple(value.items())))
+    assert canonical_json_bytes(value) == canonical_json_bytes(reversed_value)
```

Create `tests/unit/domain/test_diagnostics.py` with exactly:

```python
from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

import pytest
from pydantic import ValidationError

from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticDetailValue,
    DiagnosticSeverity,
)

_DIAGNOSTIC_ID = "diag_12345678-1234-4234-8234-123456789abc"
_CAUSE_ID = "diag_22345678-1234-4234-8234-123456789abc"


def _diagnostic(
    *,
    details: dict[str, object] | None = None,
    causes: tuple[str, ...] = (),
) -> Diagnostic:
    return Diagnostic(
        schema_version="1.0.0",
        diagnostic_id=_DIAGNOSTIC_ID,
        severity=DiagnosticSeverity.ERROR,
        error_code="CONFIG.LAYER_INVALID",
        category=DiagnosticCategory.USER_CONFIGURATION,
        message="Configuration layer is invalid.",
        source_component="configuration.loader",
        retriable=False,
        timestamp_utc=datetime(2026, 8, 10, tzinfo=UTC),
        details=cast(
            dict[str, DiagnosticDetailValue],
            {} if details is None else details,
        ),
        causal_diagnostic_ids=causes,
    )


def test_diagnostic_round_trip_and_optional_correlations() -> None:
    diagnostic = _diagnostic(details={"path_kind": "primary", "attempt": 1})
    assert Diagnostic.model_validate_json(diagnostic.model_dump_json()) == diagnostic
    dumped = diagnostic.model_dump(mode="json")
    for field in ("experiment_id", "run_id", "invocation_id", "engine"):
        assert field not in dumped


@pytest.mark.parametrize(
    "field",
    ["experiment_id", "run_id", "invocation_id", "engine"],
)
def test_optional_correlations_reject_explicit_null(field: str) -> None:
    payload = _diagnostic().model_dump(mode="python")
    payload[field] = None
    with pytest.raises(ValidationError):
        Diagnostic.model_validate(payload)


@pytest.mark.parametrize(
    "error_code",
    ["invalid", "CONFIG", "CONFIG.bad", ".CONFIG.INVALID", "CONFIG.INVALID!"],
)
def test_error_code_must_be_uppercase_and_namespaced(error_code: str) -> None:
    payload = _diagnostic().model_dump(mode="python")
    payload["error_code"] = error_code
    with pytest.raises(ValidationError):
        Diagnostic.model_validate(payload)


@pytest.mark.parametrize(
    "details",
    [
        {"api_key": "forbidden"},
        {"nested": {"Auth-Token": "forbidden"}},
        {"nested": {"customer_api_key": "forbidden"}},
        {"apiKey": "forbidden"},
        {"accessToken": "forbidden"},
        {"authToken": "forbidden"},
        {"attemptToken": "forbidden"},
        {"credentials": "forbidden"},
        {"ratio": 0.5},
        {"count": 2**63},
        {"count": -(2**63) - 1},
        {"message": "x" * 2049},
        {"items": list(range(65))},
    ],
)
def test_details_reject_secrets_floats_and_bounds(
    details: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _diagnostic(details=details)


def test_details_reject_excessive_depth() -> None:
    nested: object = "leaf"
    for _ in range(10):
        nested = {"nested": nested}
    with pytest.raises(ValidationError, match="maximum depth"):
        _diagnostic(details={"root": nested})


def test_details_reject_excessive_node_count() -> None:
    groups = [{f"key{index}": index for index in range(64)} for _ in range(4)]
    with pytest.raises(ValidationError, match="too many nodes"):
        _diagnostic(details={"groups": groups})


def test_details_reject_excessive_encoded_bytes() -> None:
    with pytest.raises(ValidationError, match="encoded bytes"):
        _diagnostic(details={"payload": ["x" * 2_048 for _ in range(8)]})


@pytest.mark.parametrize(
    "category",
    [
        DiagnosticCategory.ENGINE_RUNTIME,
        DiagnosticCategory.PROTOCOL,
        DiagnosticCategory.TIMEOUT,
        DiagnosticCategory.CANCELLATION,
    ],
)
def test_command_process_and_protocol_findings_require_invocation(
    category: DiagnosticCategory,
) -> None:
    payload = _diagnostic().model_dump(mode="python")
    payload["category"] = category
    with pytest.raises(ValidationError, match="requires invocation"):
        Diagnostic.model_validate(payload)


def test_describe_invocation_does_not_invent_run_or_experiment() -> None:
    payload = _diagnostic().model_dump(mode="python")
    payload["category"] = DiagnosticCategory.ENGINE_RUNTIME
    payload["invocation_id"] = "inv_12345678-1234-4234-8234-123456789abc"
    diagnostic = Diagnostic.model_validate(payload)
    assert diagnostic.invocation_id == "inv_12345678-1234-4234-8234-123456789abc"
    dumped = diagnostic.model_dump(mode="json")
    assert "run_id" not in dumped
    assert "experiment_id" not in dumped


@pytest.mark.parametrize("causes", [(_CAUSE_ID, _CAUSE_ID), (_DIAGNOSTIC_ID,)])
def test_causal_ids_are_unique_and_not_self_referential(
    causes: tuple[str, ...],
) -> None:
    with pytest.raises(ValidationError):
        _diagnostic(causes=causes)


def test_diagnostic_rejects_unknown_fields() -> None:
    payload = _diagnostic().model_dump(mode="python")
    marker = "INPUT_MARKER_MUST_NOT_APPEAR"
    payload["customer_api_key"] = marker
    with pytest.raises(
        ValidationError,
        match="extra_forbidden",
    ) as captured:
        Diagnostic.model_validate(payload)
    assert marker not in str(captured.value)
```

---

### A.10 Exact configuration and dataset test files

Create `tests/unit/configuration/test_models.py` with exactly:

```python
from __future__ import annotations

import json

import pytest
from pydantic import BaseModel, ValidationError

from crypto_lab.configuration.models import (
    AdapterEntryConfig,
    AdaptersConfig,
    ApplicationConfig,
    CliOverrides,
    ConfigurationLayer,
    DatabaseConfig,
    LoggingConfig,
    PathsConfig,
    PolicyConfig,
    ProcessConfig,
    ProtocolConfig,
    RetryConfig,
    SchedulerConfig,
)

_HASH = "a" * 64


def _adapter(name: str, version: str) -> AdapterEntryConfig:
    return AdapterEntryConfig(
        adapter_name=name,
        adapter_version=version,
        executable_path=r"C:\adapters\adapter.exe",
        executable_hash=_HASH,
    )


def test_compiled_defaults_match_the_fixed_table() -> None:
    config = ApplicationConfig()
    assert config.schema_version == "1.0.0"
    assert config.paths.model_dump() == {
        "runtime_root": "runtime",
        "data_root": "data",
        "artifacts_root": "artifacts",
        "logs_root": "logs",
        "runtimes_root": "runtimes",
    }
    assert config.database == DatabaseConfig()
    assert config.scheduler == SchedulerConfig()
    assert config.process == ProcessConfig()
    assert config.protocol == ProtocolConfig()
    assert config.logging == LoggingConfig()
    assert config.adapters == AdaptersConfig()
    assert config.policy == PolicyConfig()


@pytest.mark.parametrize(
    ("model_type", "payload"),
    [
        (PathsConfig, {"unexpected": 1}),
        (DatabaseConfig, {"unexpected": 1}),
        (RetryConfig, {"unexpected": 1}),
        (SchedulerConfig, {"unexpected": 1}),
        (ProcessConfig, {"unexpected": 1}),
        (ProtocolConfig, {"unexpected": 1}),
        (LoggingConfig, {"unexpected": 1}),
        (AdaptersConfig, {"unexpected": 1}),
        (PolicyConfig, {"unexpected": 1}),
        (ApplicationConfig, {"unexpected": 1}),
        (ConfigurationLayer, {"schema_version": "1.0.0", "unexpected": 1}),
    ],
)
def test_every_configuration_boundary_rejects_unknown_fields(
    model_type: type[BaseModel],
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        model_type.model_validate(payload)


def test_nested_partial_layer_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ConfigurationLayer.model_validate(
            {
                "schema_version": "1.0.0",
                "scheduler": {"retry": {"unexpected": 1}},
            }
        )


@pytest.mark.parametrize(
    "section",
    [
        "paths",
        "database",
        "scheduler",
        "process",
        "protocol",
        "logging",
        "adapters",
        "policy",
    ],
)
def test_every_partial_section_rejects_unknown_fields(section: str) -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ConfigurationLayer.model_validate(
            {"schema_version": "1.0.0", section: {"unexpected": 1}}
        )


@pytest.mark.parametrize(
    "payload",
    [
        {"database": {"busy_timeout_ms": 99}},
        {"database": {"busy_timeout_ms": 60001}},
        {"scheduler": {"max_concurrent_runs": 0}},
        {"scheduler": {"max_concurrent_runs": 9}},
        {"scheduler": {"retry": {"maximum_attempts_per_slot": 0}}},
        {"scheduler": {"retry": {"maximum_attempts_per_slot": 6}}},
        {"scheduler": {"retry": {"retry_delay_seconds": -1}}},
        {"scheduler": {"retry": {"retry_delay_seconds": 301}}},
        {"process": {"heartbeat_interval_seconds": 0}},
        {"process": {"heartbeat_interval_seconds": 301}},
        {"process": {"missing_heartbeat_seconds": 1}},
        {"process": {"missing_heartbeat_seconds": 901}},
        {"process": {"describe_timeout_seconds": 0}},
        {"process": {"describe_timeout_seconds": 301}},
        {"process": {"validate_timeout_seconds": 0}},
        {"process": {"validate_timeout_seconds": 1801}},
        {"process": {"default_run_timeout_seconds": 0}},
        {"process": {"default_run_timeout_seconds": 604801}},
        {"process": {"finalization_timeout_seconds": 0}},
        {"process": {"finalization_timeout_seconds": 3601}},
        {"process": {"cancellation_grace_seconds": -1}},
        {"process": {"cancellation_grace_seconds": 301}},
        {"protocol": {"max_event_bytes": 4095}},
        {"protocol": {"max_event_bytes": 1048577}},
        {"protocol": {"max_manifest_bytes": 65535}},
        {"protocol": {"max_manifest_bytes": 16777217}},
        {"logging": {"max_stderr_bytes_per_invocation": 1048575}},
        {"logging": {"max_stderr_bytes_per_invocation": 52428801}},
        {"logging": {"retained_files": 0}},
        {"logging": {"retained_files": 101}},
    ],
)
def test_numeric_values_fail_outside_the_fixed_bounds(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        ApplicationConfig.model_validate(payload)


@pytest.mark.parametrize(
    "payload",
    [
        {"database": {"busy_timeout_ms": 100}},
        {"database": {"busy_timeout_ms": 60_000}},
        {"scheduler": {"max_concurrent_runs": 1}},
        {"scheduler": {"max_concurrent_runs": 8}},
        {"scheduler": {"retry": {"maximum_attempts_per_slot": 1}}},
        {"scheduler": {"retry": {"maximum_attempts_per_slot": 5}}},
        {"scheduler": {"retry": {"retry_delay_seconds": 0}}},
        {"scheduler": {"retry": {"retry_delay_seconds": 300}}},
        {
            "process": {
                "heartbeat_interval_seconds": 1,
                "missing_heartbeat_seconds": 2,
            }
        },
        {
            "process": {
                "heartbeat_interval_seconds": 300,
                "missing_heartbeat_seconds": 900,
            }
        },
        {"process": {"describe_timeout_seconds": 1}},
        {"process": {"describe_timeout_seconds": 300}},
        {"process": {"validate_timeout_seconds": 1}},
        {"process": {"validate_timeout_seconds": 1_800}},
        {"process": {"default_run_timeout_seconds": 1}},
        {"process": {"default_run_timeout_seconds": 604_800}},
        {"process": {"finalization_timeout_seconds": 1}},
        {"process": {"finalization_timeout_seconds": 3_600}},
        {"process": {"cancellation_grace_seconds": 0}},
        {"process": {"cancellation_grace_seconds": 300}},
        {"protocol": {"max_event_bytes": 4_096}},
        {"protocol": {"max_event_bytes": 1_048_576}},
        {"protocol": {"max_manifest_bytes": 65_536}},
        {"protocol": {"max_manifest_bytes": 16_777_216}},
        {"logging": {"max_stderr_bytes_per_invocation": 1_048_576}},
        {"logging": {"max_stderr_bytes_per_invocation": 52_428_800}},
        {"logging": {"retained_files": 1}},
        {"logging": {"retained_files": 100}},
    ],
)
def test_numeric_values_accept_both_fixed_bounds(payload: dict[str, object]) -> None:
    ApplicationConfig.model_validate(payload)


def test_heartbeat_ratio_and_retry_normalization() -> None:
    with pytest.raises(ValidationError, match="at least twice"):
        ProcessConfig(
            heartbeat_interval_seconds=30,
            missing_heartbeat_seconds=59,
        )
    retry = RetryConfig(automatically_retry_terminal_states=("UNAVAILABLE", "FAILED"))
    assert retry.automatically_retry_terminal_states == (
        "FAILED",
        "UNAVAILABLE",
    )
    with pytest.raises(ValidationError, match="unique"):
        RetryConfig(automatically_retry_terminal_states=("FAILED", "FAILED"))
    with pytest.raises(ValidationError, match="foreign"):
        RetryConfig(automatically_retry_terminal_states=("CANCELLED",))
    with pytest.raises(ValidationError):
        RetryConfig(require_fresh_availability_observation_for_unavailable=False)


def test_adapter_catalog_is_sorted_unique_and_rejects_secret_like_keys() -> None:
    first = _adapter("adapter.alpha", "1.0.0")
    second = _adapter("adapter.beta", "1.0.0")
    assert AdaptersConfig(entries=(first, second)).entries == (first, second)
    with pytest.raises(ValidationError, match="ordered"):
        AdaptersConfig(entries=(second, first))
    with pytest.raises(ValidationError, match="unique"):
        AdaptersConfig(entries=(first, first))
    colliding = first.model_copy(update={"executable_hash": "b" * 64})
    with pytest.raises(ValidationError, match="unique"):
        AdaptersConfig(entries=(first, colliding))
    with pytest.raises(ValidationError, match="secret-like"):
        AdapterEntryConfig(
            adapter_name="adapter.alpha",
            adapter_version="1.0.0",
            executable_path=r"C:\adapter.exe",
            executable_hash=_HASH,
            runtime_metadata={"nested": {"nested_api_key_value": "forbidden"}},
        )
    for invalid_metadata in (
        {"attempt_token": "raw-token-is-forbidden"},
        {"apiKey": "forbidden"},
        {"accessToken": "forbidden"},
        {"authToken": "forbidden"},
        {"attemptToken": "forbidden"},
        {"credentials": "forbidden"},
        {"ratio": 0.5},
        {"count": 2**63},
        {"count": -(2**63) - 1},
    ):
        with pytest.raises(ValidationError):
            AdapterEntryConfig.model_validate(
                {
                    "adapter_name": "adapter.alpha",
                    "adapter_version": "1.0.0",
                    "executable_path": r"C:\adapter.exe",
                    "executable_hash": _HASH,
                    "runtime_metadata": invalid_metadata,
                }
            )


def test_runtime_metadata_rejects_depth_nodes_and_encoded_bytes() -> None:
    nested: object = "leaf"
    for _ in range(10):
        nested = {"nested": nested}
    groups = [{f"key{index}": index for index in range(64)} for _ in range(4)]
    for metadata, message in (
        ({"root": nested}, "maximum depth"),
        ({"groups": groups}, "too many nodes"),
        ({"payload": ["x" * 2_048 for _ in range(8)]}, "encoded bytes"),
    ):
        with pytest.raises(ValidationError, match=message):
            AdapterEntryConfig(
                adapter_name="adapter.alpha",
                adapter_version="1.0.0",
                executable_path=r"C:\adapter.exe",
                executable_hash=_HASH,
                runtime_metadata=metadata,
            )


def test_adapter_catalog_has_a_compiled_maximum_of_32_entries() -> None:
    entries = tuple(
        _adapter(f"adapter.item{index:02d}", "1.0.0") for index in range(32)
    )
    assert AdaptersConfig(entries=entries).entries == entries
    with pytest.raises(ValidationError):
        AdaptersConfig(
            entries=(
                *entries,
                _adapter("adapter.overflow", "1.0.0"),
            )
        )


@pytest.mark.parametrize(
    "value",
    [
        r"C:drive-relative",
        r"\rooted-without-drive",
        r"\\server\share",
        "folder//child",
        "folder/./child",
        "folder/name:stream",
        "folder/CON",
        "folder/trailing. ",
        "folder/root?/file",
        "folder/bad<name",
        "folder/control\x1f",
    ],
)
def test_application_path_models_reject_unsafe_windows_syntax(value: str) -> None:
    with pytest.raises(ValidationError):
        PathsConfig(runtime_root=value)


def test_emitted_path_patterns_are_ecma_262_portable() -> None:
    encoded = json.dumps(ApplicationConfig.model_json_schema(mode="serialization"))
    assert "(?i" not in encoded
    assert "[Aa][Uu][Xx]" in encoded


@pytest.mark.parametrize(
    "value",
    [
        "relative.exe",
        r"\\server\share\adapter.exe",
        r"C:\adapters\bad?.exe",
        r"C:\adapters\CON.exe",
        r"C:\adapters\name.exe:stream",
    ],
)
def test_adapter_executable_requires_safe_absolute_local_path(value: str) -> None:
    with pytest.raises(ValidationError):
        AdapterEntryConfig(
            adapter_name="adapter.alpha",
            adapter_version="1.0.0",
            executable_path=value,
            executable_hash=_HASH,
        )


def test_policy_is_literal_false_and_cli_surface_is_closed() -> None:
    for field in ("allow_network", "allow_credentials", "allow_live"):
        with pytest.raises(ValidationError):
            PolicyConfig.model_validate({field: True})
    assert set(CliOverrides.model_fields) == {
        "runtime_root",
        "data_root",
        "artifacts_root",
        "logs_root",
        "runtimes_root",
        "max_concurrent_runs",
        "maximum_attempts_per_slot",
        "automatically_retry_terminal_states",
        "retry_delay_seconds",
        "heartbeat_interval_seconds",
        "missing_heartbeat_seconds",
        "describe_timeout_seconds",
        "validate_timeout_seconds",
        "default_run_timeout_seconds",
        "finalization_timeout_seconds",
        "cancellation_grace_seconds",
    }
    with pytest.raises(ValidationError, match="extra_forbidden"):
        CliOverrides.model_validate({"allow_network": False})


def test_filename_path_and_foreign_policy_keys_are_rejected() -> None:
    for filename in (
        "../database.sqlite3",
        "CON",
        "nul.sqlite3",
        "database.sqlite3.",
        "database.sqlite3 ",
        "database:stream",
    ):
        with pytest.raises(ValidationError):
            DatabaseConfig(filename=filename)
    with pytest.raises(ValidationError):
        PathsConfig(runtime_root="")
    for key in ("shell", "shorting", "margin", "futures", "leverage"):
        with pytest.raises(ValidationError, match="extra_forbidden"):
            PolicyConfig.model_validate({key: False})
```

Create `tests/unit/configuration/test_loader.py` with exactly:

```python
from __future__ import annotations

import os
import socket
import urllib.request
from pathlib import Path
from typing import Never

import pytest

from crypto_lab.configuration.loader import ConfigurationError, load_configuration
from crypto_lab.configuration.models import MAX_CONFIGURATION_BYTES, CliOverrides

_HASH = "a" * 64


def _write(path: Path, contents: str) -> Path:
    path.write_text(contents, encoding="utf-8")
    return path


def _forbidden(*_args: object, **_kwargs: object) -> Never:
    raise AssertionError("ambient source was accessed")


class ForbiddenEnvironment:
    def __getitem__(self, _key: str) -> Never:
        raise AssertionError("environment was accessed")

    def get(self, _key: str, _default: object = None) -> Never:
        raise AssertionError("environment was accessed")


def test_precedence_is_defaults_primary_local_cli(tmp_path: Path) -> None:
    primary = _write(
        tmp_path / "primary.toml",
        """
schema_version = "1.0.0"
[paths]
runtime_root = "primary-runtime"
[scheduler]
max_concurrent_runs = 2
""".strip(),
    )
    local = _write(
        tmp_path / "local.toml",
        """
schema_version = "1.0.0"
[paths]
runtime_root = "local-runtime"
[scheduler]
max_concurrent_runs = 3
""".strip(),
    )
    config = load_configuration(
        primary_path=primary,
        local_override_path=local,
        cli_overrides=CliOverrides(
            runtime_root="cli-runtime",
            max_concurrent_runs=4,
        ),
        invocation_base=tmp_path,
    )
    assert config.paths.runtime_root == str(tmp_path / "cli-runtime")
    assert config.paths.data_root == str(tmp_path / "data")
    assert config.scheduler.max_concurrent_runs == 4


def test_default_paths_use_explicit_invocation_base(tmp_path: Path) -> None:
    config = load_configuration(
        primary_path=None,
        local_override_path=None,
        cli_overrides=None,
        invocation_base=tmp_path,
    )
    assert config.paths.runtime_root == str(tmp_path / "runtime")
    assert config.paths.data_root == str(tmp_path / "data")


@pytest.mark.parametrize(
    ("primary", "local", "base", "code"),
    [
        (
            Path("relative.toml"),
            None,
            Path("C:/base"),
            "PRIMARY_PATH_NOT_ABSOLUTE",
        ),
        (
            None,
            Path("relative.toml"),
            Path("C:/base"),
            "OVERRIDE_REQUIRES_PRIMARY",
        ),
        (None, None, Path("relative"), "INVOCATION_BASE_PATH_NOT_ABSOLUTE"),
    ],
)
def test_relative_or_unpaired_sources_are_rejected(
    primary: Path | None,
    local: Path | None,
    base: Path,
    code: str,
) -> None:
    with pytest.raises(ConfigurationError, match=code):
        load_configuration(
            primary_path=primary,
            local_override_path=local,
            cli_overrides=None,
            invocation_base=base,
        )


@pytest.mark.parametrize(
    "contents",
    [
        "",
        'schema_version = "2.0.0"',
        'schema_version = "1.0.0"\nunknown = true',
        'schema_version = "1.0.0"\n[paths\nruntime_root = "x"',
    ],
)
def test_invalid_layers_use_one_path_only_error(
    tmp_path: Path,
    contents: str,
) -> None:
    primary = _write(tmp_path / "primary.toml", contents)
    with pytest.raises(
        ConfigurationError,
        match=r"CONFIG\.LAYER_INVALID",
    ) as captured:
        load_configuration(
            primary_path=primary,
            local_override_path=None,
            cli_overrides=None,
            invocation_base=tmp_path,
        )
    assert contents not in str(captured.value)


def test_oversized_layer_is_rejected_before_decode_or_parse(tmp_path: Path) -> None:
    primary = tmp_path / "oversized.toml"
    primary.write_bytes(b"x" * (MAX_CONFIGURATION_BYTES + 1))
    with pytest.raises(ConfigurationError, match=r"CONFIG\.LAYER_TOO_LARGE"):
        load_configuration(
            primary_path=primary,
            local_override_path=None,
            cli_overrides=None,
            invocation_base=tmp_path,
        )


def test_local_schema_version_cannot_differ(tmp_path: Path) -> None:
    primary = _write(tmp_path / "primary.toml", 'schema_version = "1.0.0"')
    local = _write(tmp_path / "local.toml", 'schema_version = "2.0.0"')
    with pytest.raises(ConfigurationError, match=r"CONFIG\.LAYER_INVALID"):
        load_configuration(
            primary_path=primary,
            local_override_path=local,
            cli_overrides=None,
            invocation_base=tmp_path,
        )


def test_unsafe_roots_and_relative_adapter_executables_fail(
    tmp_path: Path,
) -> None:
    unsafe = _write(
        tmp_path / "unsafe.toml",
        'schema_version = "1.0.0"\n[paths]\nruntime_root = "../escape"',
    )
    with pytest.raises(ConfigurationError, match=r"CONFIG\.UNSAFE_PATH"):
        load_configuration(
            primary_path=unsafe,
            local_override_path=None,
            cli_overrides=None,
            invocation_base=tmp_path,
        )
    adapter = _write(
        tmp_path / "adapter.toml",
        f"""
schema_version = "1.0.0"
[[adapters.entries]]
adapter_name = "adapter.alpha"
adapter_version = "1.0.0"
executable_path = "relative.exe"
executable_hash = "{_HASH}"
runtime_metadata = {{}}
""".strip(),
    )
    with pytest.raises(
        ConfigurationError,
        match=r"CONFIG\.ADAPTER_EXECUTABLE_NOT_ABSOLUTE",
    ):
        load_configuration(
            primary_path=adapter,
            local_override_path=None,
            cli_overrides=None,
            invocation_base=tmp_path,
        )


@pytest.mark.parametrize(
    "value",
    [
        r"C:drive-relative",
        r"\rooted-without-drive",
        r"\\server\share",
        "folder//child",
        "folder/./child",
        "folder/name:stream",
        "folder/CON",
        "folder/trailing. ",
        "folder/root?/file",
        "folder/bad<name",
        "folder/control\x1f",
    ],
)
def test_cli_roots_reject_unsafe_windows_syntax(
    tmp_path: Path,
    value: str,
) -> None:
    with pytest.raises(ConfigurationError, match=r"CONFIG\.UNSAFE_PATH"):
        load_configuration(
            primary_path=None,
            local_override_path=None,
            cli_overrides=CliOverrides(runtime_root=value),
            invocation_base=tmp_path,
        )


def test_explicit_loading_uses_no_ambient_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = _write(tmp_path / "primary.toml", 'schema_version = "1.0.0"')
    monkeypatch.setattr(os, "getenv", _forbidden)
    monkeypatch.setattr(os, "environ", ForbiddenEnvironment())
    monkeypatch.setattr(Path, "home", _forbidden)
    monkeypatch.setattr(Path, "cwd", _forbidden)
    monkeypatch.setattr(Path, "expanduser", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", _forbidden)
    config = load_configuration(
        primary_path=primary,
        local_override_path=None,
        cli_overrides=None,
        invocation_base=tmp_path,
    )
    assert config.schema_version == "1.0.0"


def test_implicit_config_file_is_never_discovered(tmp_path: Path) -> None:
    _write(
        tmp_path / "config.toml",
        'schema_version = "1.0.0"\n[scheduler]\nmax_concurrent_runs = 8',
    )
    config = load_configuration(
        primary_path=None,
        local_override_path=None,
        cli_overrides=None,
        invocation_base=tmp_path,
    )
    assert config.scheduler.max_concurrent_runs == 1
```

Create `tests/unit/configuration/test_snapshot.py` with exactly:

```python
from __future__ import annotations

import pytest
from pydantic import JsonValue, ValidationError

from crypto_lab.configuration.models import (
    AdapterEntryConfig,
    AdaptersConfig,
    ApplicationConfig,
    DatabaseConfig,
    LoggingConfig,
    PathsConfig,
    ProcessConfig,
    ProtocolConfig,
    RetryConfig,
    SchedulerConfig,
)
from crypto_lab.configuration.snapshot import (
    ConfigSnapshot,
    configuration_audit_hash,
    material_base_configuration_hash,
    snapshot_configuration,
)
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.hashing import HashingProfile, profile_hash


def _replace(
    config: ApplicationConfig,
    field: str,
    value: object,
) -> ApplicationConfig:
    payload = config.model_dump(mode="python")
    payload[field] = value
    return ApplicationConfig.model_validate(payload)


def _catalog() -> AdaptersConfig:
    return AdaptersConfig(
        entries=(
            AdapterEntryConfig(
                adapter_name="adapter.alpha",
                adapter_version="1.0.0",
                executable_path=r"C:\adapter.exe",
                executable_hash="a" * 64,
            ),
        )
    )


def test_audit_hash_changes_for_every_configuration_section() -> None:
    base = ApplicationConfig()
    variants = (
        _replace(base, "paths", PathsConfig(runtime_root="other")),
        _replace(base, "database", DatabaseConfig(busy_timeout_ms=6000)),
        _replace(
            base,
            "scheduler",
            SchedulerConfig(max_concurrent_runs=2, retry=base.scheduler.retry),
        ),
        _replace(base, "process", ProcessConfig(describe_timeout_seconds=31)),
        _replace(base, "protocol", ProtocolConfig(max_event_bytes=4097)),
        _replace(
            base,
            "logging",
            LoggingConfig(
                max_stderr_bytes_per_invocation=52_428_800,
                retained_files=11,
            ),
        ),
        _replace(base, "adapters", _catalog()),
    )
    baseline = configuration_audit_hash(base)
    assert all(configuration_audit_hash(item) != baseline for item in variants)


def test_material_hash_has_the_exact_operational_exclusions() -> None:
    base = ApplicationConfig()
    variants = (
        _replace(base, "paths", PathsConfig(runtime_root="other")),
        _replace(base, "database", DatabaseConfig(busy_timeout_ms=6000)),
        _replace(
            base,
            "scheduler",
            SchedulerConfig(max_concurrent_runs=2, retry=base.scheduler.retry),
        ),
        _replace(
            base,
            "logging",
            LoggingConfig(
                max_stderr_bytes_per_invocation=(
                    base.logging.max_stderr_bytes_per_invocation
                ),
                retained_files=11,
            ),
        ),
        _replace(base, "adapters", _catalog()),
    )
    baseline = material_base_configuration_hash(base)
    assert all(material_base_configuration_hash(item) == baseline for item in variants)


def test_material_hash_changes_for_each_variable_material_section() -> None:
    base = ApplicationConfig()
    variants = (
        _replace(
            base,
            "scheduler",
            SchedulerConfig(retry=RetryConfig(maximum_attempts_per_slot=2)),
        ),
        _replace(base, "process", ProcessConfig(describe_timeout_seconds=31)),
        _replace(base, "protocol", ProtocolConfig(max_event_bytes=4097)),
        _replace(
            base,
            "logging",
            LoggingConfig(max_stderr_bytes_per_invocation=1_048_576),
        ),
    )
    baseline = material_base_configuration_hash(base)
    assert all(material_base_configuration_hash(item) != baseline for item in variants)


def test_fixed_policy_is_present_in_the_material_projection() -> None:
    config = ApplicationConfig()
    payload: dict[str, JsonValue] = {
        "scheduler": {"retry": config.scheduler.retry.model_dump(mode="json")},
        "process": config.process.model_dump(mode="json"),
        "protocol": config.protocol.model_dump(mode="json"),
        "logging": {
            "max_stderr_bytes_per_invocation": (
                config.logging.max_stderr_bytes_per_invocation
            )
        },
        "policy": config.policy.model_dump(mode="json"),
    }
    assert material_base_configuration_hash(config) == profile_hash(
        HashingProfile.CONFIGURATION_MATERIAL_BASE_V1,
        payload,
    )


def test_snapshot_and_hashes_are_deterministic_under_key_ordering() -> None:
    left = ApplicationConfig.model_validate(
        {"scheduler": {"max_concurrent_runs": 2}, "schema_version": "1.0.0"}
    )
    right = ApplicationConfig.model_validate(
        {"schema_version": "1.0.0", "scheduler": {"max_concurrent_runs": 2}}
    )
    left_snapshot = snapshot_configuration(left)
    right_snapshot = snapshot_configuration(right)
    assert left_snapshot == right_snapshot
    assert canonical_json_bytes(left_snapshot) == canonical_json_bytes(right_snapshot)
    assert left_snapshot.configuration_audit_hash == configuration_audit_hash(left)


def test_snapshot_retains_immutable_canonical_text_after_source_mutation() -> None:
    config = ApplicationConfig(adapters=_catalog())
    entry = config.adapters.entries[0]
    entry.runtime_metadata["nested"] = {"mode": "safe"}
    snapshot = snapshot_configuration(config)
    snapshot_bytes = canonical_json_bytes(snapshot)
    entry.runtime_metadata["nested"] = {"mode": "changed"}
    assert canonical_json_bytes(snapshot) == snapshot_bytes
    restored = ApplicationConfig.model_validate_json(snapshot.configuration_json)
    assert restored.adapters.entries[0].runtime_metadata == {"nested": {"mode": "safe"}}


def test_hash_and_snapshot_boundaries_revalidate_mutated_nested_metadata() -> None:
    config = ApplicationConfig(adapters=_catalog())
    config.adapters.entries[0].runtime_metadata["customer_api_key"] = "forbidden"
    with pytest.raises(ValidationError, match="secret-like"):
        configuration_audit_hash(config)
    with pytest.raises(ValidationError, match="secret-like"):
        material_base_configuration_hash(config)
    with pytest.raises(ValidationError, match="secret-like"):
        snapshot_configuration(config)


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        (
            "configuration_json",
            '{ "schema_version": "1.0.0" }',
            "not canonical",
        ),
        ("configuration_audit_hash", "b" * 64, "audit hash mismatch"),
        (
            "material_base_configuration_hash",
            "c" * 64,
            "material hash mismatch",
        ),
    ],
)
def test_direct_snapshot_validation_recomputes_every_derived_field(
    field: str,
    replacement: str,
    message: str,
) -> None:
    payload = snapshot_configuration(ApplicationConfig()).model_dump(mode="python")
    payload[field] = replacement
    with pytest.raises(ValidationError, match=message):
        ConfigSnapshot.model_validate(payload)


def test_direct_snapshot_json_rejects_invalid_config_without_echo() -> None:
    marker = "INPUT_MARKER_MUST_NOT_APPEAR"
    payload = snapshot_configuration(ApplicationConfig()).model_dump(mode="json")
    payload["configuration_json"] = f'{{"schema_version":"1.0.0","{marker}":1}}'
    encoded = canonical_json_bytes(payload)
    with pytest.raises(ValidationError, match="snapshot JSON is invalid") as captured:
        ConfigSnapshot.model_validate_json(encoded)
    assert marker not in str(captured.value)


def test_direct_snapshot_validation_enforces_utf8_byte_ceiling_before_parse() -> None:
    payload = snapshot_configuration(ApplicationConfig()).model_dump(mode="python")
    payload["configuration_json"] = "é" * 600_000
    with pytest.raises(ValidationError, match="maximum encoded bytes"):
        ConfigSnapshot.model_validate(payload)


def test_largest_adapter_catalog_remains_snapshot_eligible() -> None:
    entries = tuple(
        AdapterEntryConfig(
            adapter_name=f"adapter.item{index:02d}",
            adapter_version="1.0.0",
            executable_path=rf"C:\adapters\item{index:02d}.exe",
            executable_hash="a" * 64,
            runtime_metadata={"description": "x" * 2_048},
        )
        for index in range(32)
    )
    snapshot = snapshot_configuration(
        ApplicationConfig(adapters=AdaptersConfig(entries=entries))
    )
    assert len(snapshot.configuration_json.encode("utf-8")) <= 1_048_576
```

Create `tests/unit/datasets/test_models.py` with exactly:

```python
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from crypto_lab.datasets.models import (
    DatasetDataType,
    DatasetDescriptor,
    DatasetPartition,
    DatasetValidationStatus,
    DuplicateInterval,
    RawSourceProvenance,
    TimeInterval,
)
from crypto_lab.domain.records import InstrumentRef, MarketType

_DS = "ds_12345678-1234-4234-8234-123456789abc"
_PART = "part_12345678-1234-4234-8234-123456789abc"
_START = datetime(2026, 1, 1, tzinfo=UTC)
_END = datetime(2026, 1, 2, tzinfo=UTC)
_OMIT = object()


def _provenance() -> RawSourceProvenance:
    return RawSourceProvenance(
        source_name="fixture.source",
        source_version="1.0.0",
        source_record="fixture",
        source_hash="1" * 64,
    )


def _partition(**updates: object) -> DatasetPartition:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "partition_id": _PART,
        "dataset_id": _DS,
        "ordinal": 0,
        "relative_path": "ohlcv/part.parquet",
        "content_hash": "0" * 64,
        "row_count": 10,
        "start_utc": _START,
        "end_utc": _END,
        "raw_checksum": "1" * 64,
        "normalized_checksum": "2" * 64,
        "column_schema_version": "1.0.0",
        "raw_source_provenance": (_provenance(),),
        "quality_observations": (),
    }
    payload.update(updates)
    return DatasetPartition.model_validate(payload)


def _descriptor(**updates: object) -> DatasetDescriptor:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "dataset_id": _DS,
        "content_hash": "0" * 64,
        "source": "fixture",
        "venue": "BINANCE",
        "instrument": InstrumentRef(
            schema_version="1.0.0",
            canonical_id="BINANCE:BTC/USDT:SPOT",
            venue="BINANCE",
            base_asset="BTC",
            quote_asset="USDT",
            market_type=MarketType.SPOT,
        ),
        "data_type": DatasetDataType.OHLCV,
        "timeframe": "1m",
        "start_utc": _START,
        "end_utc": _END,
        "original_timezone": "UTC",
        "normalized_to_utc": True,
        "raw_source_provenance": (_provenance(),),
        "normalization_implementation": "fixture.normalizer",
        "normalization_version": "1.0.0",
        "validation_status": DatasetValidationStatus.VALID,
        "partition_ids": (_PART,),
        "missing_intervals": (),
        "duplicate_intervals": (),
        "diagnostic_ids": (),
        "raw_checksums": ("1" * 64,),
        "normalized_checksums": ("2" * 64,),
        "column_schema_version": "1.0.0",
        "known_limitations": (),
        "created_at_utc": _END,
    }
    payload.update(updates)
    for field, value in tuple(payload.items()):
        if value is _OMIT:
            del payload[field]
    return DatasetDescriptor.model_validate(payload)


def test_dataset_models_round_trip_with_explicit_arrays() -> None:
    partition = _partition()
    descriptor = _descriptor()
    assert (
        DatasetPartition.model_validate_json(partition.model_dump_json()) == partition
    )
    assert (
        DatasetDescriptor.model_validate_json(descriptor.model_dump_json())
        == descriptor
    )
    for model, fields in (
        (partition, ("raw_source_provenance", "quality_observations")),
        (
            descriptor,
            (
                "missing_intervals",
                "duplicate_intervals",
                "diagnostic_ids",
                "known_limitations",
            ),
        ),
    ):
        for field in fields:
            payload = model.model_dump(mode="python")
            del payload[field]
            with pytest.raises(ValidationError, match="Field required"):
                type(model).model_validate(payload)


def test_absent_descriptor_fields_serialize_away_and_null_is_rejected() -> None:
    descriptor = _descriptor()
    dumped = descriptor.model_dump(mode="json")
    assert "imported_at_utc" not in dumped
    with pytest.raises(ValidationError):
        _descriptor(imported_at_utc=None)
    with pytest.raises(ValidationError):
        _descriptor(timeframe=None)


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/root/file",
        "//server/share",
        r"folder\file",
        "C:/file",
        "file:stream",
        "../file",
        "folder/../file",
        "folder//file",
        "folder/./file",
        "folder/\x00file",
        "folder/\x1ffile",
        "folder/AUX.txt",
        "con",
        "folder/file.",
        "folder/file ",
        "folder/inv*lid",
        "folder/<invalid>",
    ],
)
def test_partition_path_rejects_unsafe_raw_syntax(path: str) -> None:
    with pytest.raises(ValidationError):
        _partition(relative_path=path)


def test_partition_quality_and_duplicate_interval_rules() -> None:
    with pytest.raises(ValidationError, match="start must precede end"):
        _partition(start_utc=_END, end_utc=_START)
    with pytest.raises(ValidationError, match="requires a quality observation"):
        _partition(row_count=0)
    with pytest.raises(ValidationError, match="must be sorted"):
        _partition(quality_observations=("z", "a"))
    provenance = _provenance()
    with pytest.raises(ValidationError, match="partition provenance must be unique"):
        _partition(raw_source_provenance=(provenance, provenance))
    earlier = RawSourceProvenance(
        source_name="aaa.source",
        source_version="1.0.0",
        source_record="fixture",
        source_hash="1" * 64,
    )
    with pytest.raises(ValidationError, match="partition provenance must be sorted"):
        _partition(raw_source_provenance=(provenance, earlier))
    with pytest.raises(ValidationError):
        DuplicateInterval(
            start_utc=_START,
            end_utc=_END,
            duplicate_count=1,
        )
    assert (
        DuplicateInterval(
            start_utc=_START,
            end_utc=_END,
            duplicate_count=2,
        ).duplicate_count
        == 2
    )


def test_standalone_and_descriptor_intervals_require_valid_ordering() -> None:
    with pytest.raises(ValidationError, match="start must precede end"):
        TimeInterval(start_utc=_END, end_utc=_START)
    middle = datetime(2026, 1, 1, 12, tzinfo=UTC)
    earlier = TimeInterval(start_utc=_START, end_utc=middle)
    later = TimeInterval(start_utc=middle, end_utc=_END)
    with pytest.raises(ValidationError, match="missing intervals must be sorted"):
        _descriptor(
            missing_intervals=(later, earlier),
            validation_status=DatasetValidationStatus.VALID_WITH_WARNINGS,
        )
    earlier_duplicate = DuplicateInterval(
        start_utc=_START,
        end_utc=middle,
        duplicate_count=2,
    )
    later_duplicate = DuplicateInterval(
        start_utc=middle,
        end_utc=_END,
        duplicate_count=2,
    )
    with pytest.raises(ValidationError, match="duplicate intervals must be sorted"):
        _descriptor(
            duplicate_intervals=(later_duplicate, earlier_duplicate),
            validation_status=DatasetValidationStatus.VALID_WITH_WARNINGS,
        )


def test_descriptor_status_timeframe_and_duplicate_rules() -> None:
    with pytest.raises(ValidationError, match="start must precede end"):
        _descriptor(start_utc=_END, end_utc=_START)
    foreign_instrument = InstrumentRef(
        schema_version="1.0.0",
        canonical_id="KRAKEN:BTC/USD:SPOT",
        venue="KRAKEN",
        base_asset="BTC",
        quote_asset="USD",
        market_type=MarketType.SPOT,
    )
    with pytest.raises(ValidationError, match="venue must match instrument"):
        _descriptor(instrument=foreign_instrument)
    with pytest.raises(ValidationError, match="require a timeframe"):
        _descriptor(timeframe=_OMIT)
    with pytest.raises(ValidationError, match="prohibit a timeframe"):
        _descriptor(data_type=DatasetDataType.TRADES, timeframe="1m")
    assert (
        _descriptor(data_type=DatasetDataType.TRADES, timeframe=_OMIT).data_type
        is DatasetDataType.TRADES
    )
    with pytest.raises(ValidationError, match="requires a quality fact"):
        _descriptor(validation_status=DatasetValidationStatus.VALID_WITH_WARNINGS)
    with pytest.raises(ValidationError, match="require a diagnostic"):
        _descriptor(validation_status=DatasetValidationStatus.INVALID)
    interval = TimeInterval(start_utc=_START, end_utc=_END)
    for update in (
        {"raw_source_provenance": (_provenance(), _provenance())},
        {
            "missing_intervals": (interval, interval),
            "validation_status": DatasetValidationStatus.VALID_WITH_WARNINGS,
        },
        {"partition_ids": (_PART, _PART)},
        {"unexpected": "rejected"},
    ):
        with pytest.raises(ValidationError):
            _descriptor(**update)


def test_ordered_checksum_tuples_may_contain_valid_duplicate_hashes() -> None:
    other_partition = "part_22345678-1234-4234-8234-123456789abc"
    descriptor = _descriptor(
        partition_ids=(_PART, other_partition),
        raw_checksums=("1" * 64, "1" * 64),
        normalized_checksums=("2" * 64, "2" * 64),
    )
    assert descriptor.raw_checksums == ("1" * 64, "1" * 64)
    assert descriptor.normalized_checksums == ("2" * 64, "2" * 64)
```

Create `tests/unit/datasets/test_hashing.py` with exactly:

```python
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Never, Protocol

import pytest

from crypto_lab.datasets.hashing import (
    dataset_metadata_hash,
    validate_dataset_identity,
)
from crypto_lab.datasets.models import (
    DatasetDataType,
    DatasetDescriptor,
    DatasetPartition,
    DatasetValidationStatus,
    RawSourceProvenance,
)
from crypto_lab.domain.records import InstrumentRef, MarketType

_DS = "ds_12345678-1234-4234-8234-123456789abc"
_OTHER_DS = "ds_22345678-1234-4234-8234-123456789abc"
_PARTS = (
    "part_12345678-1234-4234-8234-123456789abc",
    "part_22345678-1234-4234-8234-123456789abc",
)
_START = datetime(2026, 1, 1, tzinfo=UTC)
_MIDDLE = datetime(2026, 1, 2, tzinfo=UTC)
_END = datetime(2026, 1, 3, tzinfo=UTC)
_DATASET_GOLDEN = "ddca79b939395b29fd0224b5d805750e23fa6e457cde84181a5de6121475a9d3"


class PartitionTransform(Protocol):
    def __call__(
        self,
        partitions: tuple[DatasetPartition, ...],
    ) -> tuple[DatasetPartition, ...]: ...


def _provenance() -> RawSourceProvenance:
    return RawSourceProvenance(
        source_name="fixture.source",
        source_version="1.0.0",
        source_record="fixture",
        source_hash="1" * 64,
    )


def _partition(
    *,
    partition_id: str,
    ordinal: int,
    start: datetime,
    end: datetime,
    raw: str,
    normalized: str,
) -> DatasetPartition:
    return DatasetPartition(
        schema_version="1.0.0",
        partition_id=partition_id,
        dataset_id=_DS,
        ordinal=ordinal,
        relative_path=f"ohlcv/{ordinal}.parquet",
        content_hash=str(ordinal + 3) * 64,
        row_count=10 + ordinal,
        start_utc=start,
        end_utc=end,
        raw_checksum=raw,
        normalized_checksum=normalized,
        column_schema_version="1.0.0",
        raw_source_provenance=(_provenance(),),
        quality_observations=(),
    )


def _rebuild_partition(
    partition: DatasetPartition,
    **updates: object,
) -> DatasetPartition:
    payload = partition.model_dump(mode="python")
    payload.update(updates)
    return DatasetPartition.model_validate(payload)


def _rebuild_descriptor(
    descriptor: DatasetDescriptor,
    **updates: object,
) -> DatasetDescriptor:
    payload = descriptor.model_dump(mode="python")
    payload.update(updates)
    return DatasetDescriptor.model_validate(payload)


def _models() -> tuple[DatasetDescriptor, tuple[DatasetPartition, ...]]:
    partitions = (
        _partition(
            partition_id=_PARTS[0],
            ordinal=0,
            start=_START,
            end=_MIDDLE,
            raw="1" * 64,
            normalized="2" * 64,
        ),
        _partition(
            partition_id=_PARTS[1],
            ordinal=1,
            start=_MIDDLE,
            end=_END,
            raw="2" * 64,
            normalized="1" * 64,
        ),
    )
    descriptor = DatasetDescriptor(
        schema_version="1.0.0",
        dataset_id=_DS,
        content_hash="0" * 64,
        source="fixture",
        venue="BINANCE",
        instrument=InstrumentRef(
            schema_version="1.0.0",
            canonical_id="BINANCE:BTC/USDT:SPOT",
            venue="BINANCE",
            base_asset="BTC",
            quote_asset="USDT",
            market_type=MarketType.SPOT,
        ),
        data_type=DatasetDataType.OHLCV,
        timeframe="1m",
        start_utc=_START,
        end_utc=_END,
        original_timezone="UTC",
        normalized_to_utc=True,
        raw_source_provenance=(_provenance(),),
        normalization_implementation="fixture.normalizer",
        normalization_version="1.0.0",
        validation_status=DatasetValidationStatus.VALID,
        partition_ids=_PARTS,
        missing_intervals=(),
        duplicate_intervals=(),
        diagnostic_ids=(),
        raw_checksums=("1" * 64, "2" * 64),
        normalized_checksums=("2" * 64, "1" * 64),
        column_schema_version="1.0.0",
        known_limitations=(),
        created_at_utc=_END,
    )
    return descriptor, partitions


def _reverse(
    partitions: tuple[DatasetPartition, ...],
) -> tuple[DatasetPartition, ...]:
    return tuple(reversed(partitions))


def _duplicate_ordinal(
    partitions: tuple[DatasetPartition, ...],
) -> tuple[DatasetPartition, ...]:
    return (partitions[0], _rebuild_partition(partitions[1], ordinal=0))


def _foreign_dataset(
    partitions: tuple[DatasetPartition, ...],
) -> tuple[DatasetPartition, ...]:
    return (
        partitions[0],
        _rebuild_partition(partitions[1], dataset_id=_OTHER_DS),
    )


_MISMATCHES: list[PartitionTransform] = [
    _reverse,
    _duplicate_ordinal,
    _foreign_dataset,
]


def test_hash_is_deterministic_and_identity_validation_is_explicit() -> None:
    descriptor, partitions = _models()
    digest = dataset_metadata_hash(descriptor, partitions)
    assert digest == _DATASET_GOLDEN
    assert dataset_metadata_hash(descriptor, partitions) == digest
    validate_dataset_identity(
        _rebuild_descriptor(descriptor, content_hash=digest),
        partitions,
    )
    with pytest.raises(ValueError, match="does not match"):
        validate_dataset_identity(descriptor, partitions)


def test_operational_fields_are_hash_invariant() -> None:
    descriptor, partitions = _models()
    baseline = dataset_metadata_hash(descriptor, partitions)
    changed_parts = tuple(
        _rebuild_partition(
            item,
            dataset_id=_OTHER_DS,
            partition_id=f"part_{index + 3}2345678-1234-4234-8234-123456789abc",
            relative_path=f"renamed/{index}.parquet",
        )
        for index, item in enumerate(partitions)
    )
    changed_descriptor = _rebuild_descriptor(
        descriptor,
        dataset_id=_OTHER_DS,
        partition_ids=tuple(item.partition_id for item in changed_parts),
        content_hash="f" * 64,
        created_at_utc=datetime(2030, 1, 1, tzinfo=UTC),
        imported_at_utc=_MIDDLE,
    )
    assert dataset_metadata_hash(changed_descriptor, changed_parts) == baseline


def test_material_fields_change_the_hash() -> None:
    descriptor, partitions = _models()
    baseline = dataset_metadata_hash(descriptor, partitions)
    changed = _rebuild_partition(partitions[0], row_count=12)
    assert dataset_metadata_hash(descriptor, (changed, partitions[1])) != baseline
    changed_content = _rebuild_partition(partitions[0], content_hash="f" * 64)
    assert (
        dataset_metadata_hash(descriptor, (changed_content, partitions[1])) != baseline
    )


@pytest.mark.parametrize("transform", list(_MISMATCHES))
def test_order_ordinal_and_dataset_mismatches_are_rejected(
    transform: PartitionTransform,
) -> None:
    descriptor, partitions = _models()
    with pytest.raises(ValueError, match=r"partition|ordinal|dataset"):
        dataset_metadata_hash(descriptor, transform(partitions))


def test_checksum_and_schema_mismatches_are_rejected() -> None:
    descriptor, partitions = _models()
    changed_descriptor = _rebuild_descriptor(
        descriptor,
        raw_checksums=tuple(reversed(descriptor.raw_checksums)),
    )
    with pytest.raises(ValueError, match="raw checksums"):
        dataset_metadata_hash(changed_descriptor, partitions)
    changed_descriptor = _rebuild_descriptor(
        descriptor,
        normalized_checksums=tuple(reversed(descriptor.normalized_checksums)),
    )
    with pytest.raises(ValueError, match="normalized checksums"):
        dataset_metadata_hash(changed_descriptor, partitions)
    changed_partition = _rebuild_partition(
        partitions[1],
        column_schema_version="2.0.0",
    )
    with pytest.raises(ValueError, match="column schema version"):
        dataset_metadata_hash(descriptor, (partitions[0], changed_partition))


def test_partition_bounds_identity_and_provenance_mismatches_are_rejected() -> None:
    descriptor, partitions = _models()
    outside = _rebuild_partition(
        partitions[0],
        start_utc=datetime(2025, 12, 31, tzinfo=UTC),
    )
    with pytest.raises(ValueError, match="bounds escape"):
        dataset_metadata_hash(descriptor, (outside, partitions[1]))
    absent_provenance = RawSourceProvenance(
        source_name="other.source",
        source_version="1.0.0",
        source_record="fixture",
        source_hash="f" * 64,
    )
    changed = _rebuild_partition(
        partitions[0],
        raw_source_provenance=(absent_provenance,),
    )
    with pytest.raises(ValueError, match="provenance is absent"):
        dataset_metadata_hash(descriptor, (changed, partitions[1]))
    wrong_identity = _rebuild_descriptor(
        descriptor,
        partition_ids=tuple(reversed(descriptor.partition_ids)),
    )
    with pytest.raises(ValueError, match="partition order"):
        dataset_metadata_hash(wrong_identity, partitions)
    wrong_ordinal = _rebuild_partition(partitions[1], ordinal=7)
    with pytest.raises(ValueError, match="ordinal"):
        dataset_metadata_hash(descriptor, (partitions[0], wrong_ordinal))


def test_hashing_never_opens_partition_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor, partitions = _models()

    def forbidden(*_args: object, **_kwargs: object) -> Never:
        raise AssertionError("dataset hashing accessed the filesystem")

    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "stat", forbidden)
    dataset_metadata_hash(descriptor, partitions)
```

Create `tests/property/test_dataset_hashing.py` with exactly:

```python
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from crypto_lab.datasets.hashing import dataset_metadata_hash
from crypto_lab.datasets.models import (
    DatasetDataType,
    DatasetDescriptor,
    DatasetPartition,
    DatasetValidationStatus,
    RawSourceProvenance,
)
from crypto_lab.domain.records import InstrumentRef, MarketType

_DS = "ds_12345678-1234-4234-8234-123456789abc"
_PART = "part_12345678-1234-4234-8234-123456789abc"
_START = datetime(2026, 1, 1, tzinfo=UTC)
_END = datetime(2026, 1, 2, tzinfo=UTC)


def _provenance() -> RawSourceProvenance:
    return RawSourceProvenance(
        source_name="fixture.source",
        source_version="1.0.0",
        source_record="fixture",
        source_hash="1" * 64,
    )


def _models(
    *,
    row_count: int = 1,
    relative_path: str = "data/part.parquet",
) -> tuple[DatasetDescriptor, DatasetPartition]:
    partition = DatasetPartition(
        schema_version="1.0.0",
        partition_id=_PART,
        dataset_id=_DS,
        ordinal=0,
        relative_path=relative_path,
        content_hash="0" * 64,
        row_count=row_count,
        start_utc=_START,
        end_utc=_END,
        raw_checksum="1" * 64,
        normalized_checksum="2" * 64,
        column_schema_version="1.0.0",
        raw_source_provenance=(_provenance(),),
        quality_observations=(),
    )
    descriptor = DatasetDescriptor(
        schema_version="1.0.0",
        dataset_id=_DS,
        content_hash="0" * 64,
        source="fixture",
        venue="BINANCE",
        instrument=InstrumentRef(
            schema_version="1.0.0",
            canonical_id="BINANCE:BTC/USDT:SPOT",
            venue="BINANCE",
            base_asset="BTC",
            quote_asset="USDT",
            market_type=MarketType.SPOT,
        ),
        data_type=DatasetDataType.OHLCV,
        timeframe="1m",
        start_utc=_START,
        end_utc=_END,
        original_timezone="UTC",
        normalized_to_utc=True,
        raw_source_provenance=(_provenance(),),
        normalization_implementation="fixture.normalizer",
        normalization_version="1.0.0",
        validation_status=DatasetValidationStatus.VALID,
        partition_ids=(_PART,),
        missing_intervals=(),
        duplicate_intervals=(),
        diagnostic_ids=(),
        raw_checksums=("1" * 64,),
        normalized_checksums=("2" * 64,),
        column_schema_version="1.0.0",
        known_limitations=(),
        created_at_utc=_END,
    )
    return descriptor, partition


def _rebuild_partition(
    partition: DatasetPartition,
    **updates: object,
) -> DatasetPartition:
    payload = partition.model_dump(mode="python")
    payload.update(updates)
    return DatasetPartition.model_validate(payload)


@given(
    row_count=st.integers(min_value=1, max_value=1_000_000),
    leaf=st.text(
        alphabet="abcdefghijklmnopqrstuvwxyz0123456789",
        min_size=1,
        max_size=16,
    ),
)
def test_hash_is_deterministic_and_material_field_sensitive(
    row_count: int,
    leaf: str,
) -> None:
    descriptor, partition = _models(
        row_count=row_count,
        relative_path=f"data/{leaf}.parquet",
    )
    baseline = dataset_metadata_hash(descriptor, (partition,))
    assert dataset_metadata_hash(descriptor, (partition,)) == baseline
    changed = _rebuild_partition(partition, row_count=row_count + 1)
    assert dataset_metadata_hash(descriptor, (changed,)) != baseline
    changed_content = _rebuild_partition(partition, content_hash="f" * 64)
    assert dataset_metadata_hash(descriptor, (changed_content,)) != baseline


@given(
    order=st.permutations(
        (
            "schema_version",
            "dataset_id",
            "content_hash",
            "source",
            "venue",
            "instrument",
            "data_type",
            "timeframe",
            "start_utc",
            "end_utc",
            "original_timezone",
            "normalized_to_utc",
            "raw_source_provenance",
            "normalization_implementation",
            "normalization_version",
            "validation_status",
            "partition_ids",
            "missing_intervals",
            "duplicate_intervals",
            "diagnostic_ids",
            "raw_checksums",
            "normalized_checksums",
            "column_schema_version",
            "known_limitations",
            "created_at_utc",
        )
    )
)
def test_descriptor_object_key_permutation_is_irrelevant(
    order: list[str],
) -> None:
    descriptor, partition = _models()
    payload = descriptor.model_dump(mode="python")
    rebuilt = DatasetDescriptor.model_validate({key: payload[key] for key in order})
    assert dataset_metadata_hash(rebuilt, (partition,)) == dataset_metadata_hash(
        descriptor,
        (partition,),
    )


@given(bad_ordinal=st.integers(min_value=1, max_value=100))
def test_generated_ordinal_mismatches_are_rejected(
    bad_ordinal: int,
) -> None:
    descriptor, partition = _models()
    changed = _rebuild_partition(partition, ordinal=bad_ordinal)
    with pytest.raises(ValueError, match="ordinal"):
        dataset_metadata_hash(descriptor, (changed,))
```

### A.11 Exact descriptor and artifact-owner test files

Create `tests/unit/adapters/test_versioning.py` with exactly:

```python
from __future__ import annotations

from typing import cast

import pytest
from pydantic import TypeAdapter, ValidationError

from crypto_lab.adapters.versioning import highest_common_stable_version
from crypto_lab.domain.versioning import SemanticVersion, parse_semantic_version


@pytest.mark.parametrize("value", ["0.0.0", "1.2.3", "10.20.300"])
def test_semantic_version_accepts_canonical_stable_values(value: str) -> None:
    assert TypeAdapter(SemanticVersion).validate_python(value) == value
    assert parse_semantic_version(value) == tuple(
        int(component) for component in value.split(".")
    )


@pytest.mark.parametrize(
    "value",
    [
        "latest",
        "v1.2.3",
        "1.2",
        "1.2.3.4",
        "1.2.3-alpha",
        "1.2.3+build",
        "01.2.3",
        "1.02.3",
        "1.2.03",
        " 1.2.3",
        "1.2.3 ",
    ],
)
def test_semantic_version_rejects_noncanonical_values(value: str) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(SemanticVersion).validate_python(value)


def test_highest_common_version_is_numeric_set_intersection() -> None:
    core: tuple[SemanticVersion, ...] = ("1.9.0", "1.10.0", "2.0.0")
    adapter: tuple[SemanticVersion, ...] = ("1.10.0", "1.9.0", "3.0.0")
    original_core = core
    original_adapter = adapter
    assert highest_common_stable_version(core, adapter) == "1.10.0"
    assert core == original_core
    assert adapter == original_adapter
    assert highest_common_stable_version(("1.0.0",), ("2.0.0",)) is None


@pytest.mark.parametrize(
    ("core", "adapter"),
    [
        (("1.0.0", "1.0.0"), ("1.0.0",)),
        (("1.0.0",), ("1.0.0", "1.0.0")),
    ],
)
def test_highest_common_version_rejects_duplicates(
    core: tuple[SemanticVersion, ...],
    adapter: tuple[SemanticVersion, ...],
) -> None:
    with pytest.raises(ValueError, match="must be unique"):
        highest_common_stable_version(core, adapter)


@pytest.mark.parametrize(
    ("core", "adapter"),
    [
        (("1.0.0", "not-a-version"), ("1.0.0",)),
        (("1.0.0",), ("1.0.0", "not-a-version")),
        (("not-a-version",), ("2.0.0",)),
    ],
)
def test_highest_common_version_validates_every_input_before_intersection(
    core: tuple[str, ...],
    adapter: tuple[str, ...],
) -> None:
    with pytest.raises(ValueError, match="stable canonical"):
        highest_common_stable_version(
            cast(tuple[SemanticVersion, ...], core),
            cast(tuple[SemanticVersion, ...], adapter),
        )
```

Create `tests/unit/adapters/test_descriptors.py` with exactly:

```python
from __future__ import annotations

import os
import socket
import subprocess
from typing import Never

import pytest
from pydantic import ValidationError

from crypto_lab.adapters.descriptors import (
    AdapterDescriptor,
    EngineDescriptor,
    OperatingSystem,
    SupportedSchemaVersion,
)


def _engine() -> EngineDescriptor:
    return EngineDescriptor(
        schema_version="1.0.0",
        engine_name="engine.alpha",
        engine_version="1.2.3",
        engine_family="engine.family",
        planned_role="Research simulation.",
        known_limitations=("No live trading.",),
    )


def _schema(name: str, version: str) -> SupportedSchemaVersion:
    return SupportedSchemaVersion(schema_name=name, schema_version=version)


def _adapter(**updates: object) -> AdapterDescriptor:
    payload = {
        "schema_version": "1.0.0",
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "engine": _engine(),
        "supported_protocol_versions": ("1.0.0", "1.10.0"),
        "supported_schema_versions": (
            _schema("domain.instrument-ref", "1.0.0"),
            _schema("domain.money", "1.0.0"),
        ),
        "capability_vocabulary_version": "capabilities/v1",
        "native_capabilities": ("market.unknown_but_normalized",),
        "approximated_capabilities": (),
        "unsupported_capabilities": ("orders.live",),
        "supported_operating_systems": (OperatingSystem.WINDOWS,),
        "runtime_requirements": ("CPython 3.12",),
        "network_required": True,
        "credentials_required": True,
        "known_modeling_limitations": ("No exchange connectivity.",),
        "executable_hash": "a" * 64,
    }
    payload.update(updates)
    return AdapterDescriptor.model_validate(payload)


def _forbidden(*_args: object, **_kwargs: object) -> Never:
    raise AssertionError("descriptor construction performed runtime work")


def test_structural_descriptor_accepts_unknown_normalized_capability() -> None:
    descriptor = _adapter()
    assert descriptor.native_capabilities == ("market.unknown_but_normalized",)
    assert descriptor.network_required is True
    assert descriptor.credentials_required is True


def test_supported_schema_versions_are_structured_sorted_and_unique() -> None:
    descriptor = _adapter()
    assert descriptor.supported_schema_versions[0] == _schema(
        "domain.instrument-ref",
        "1.0.0",
    )
    for invalid in (
        (
            _schema("domain.money", "1.0.0"),
            _schema("domain.instrument-ref", "1.0.0"),
        ),
        (
            _schema("domain.money", "1.0.0"),
            _schema("domain.money", "1.0.0"),
        ),
        (
            _schema("domain.money", "1.10.0"),
            _schema("domain.money", "1.9.0"),
        ),
    ):
        with pytest.raises(ValidationError):
            _adapter(supported_schema_versions=invalid)


@pytest.mark.parametrize(
    "updates",
    [
        {"supported_protocol_versions": ("1.10.0", "1.9.0")},
        {"supported_protocol_versions": ("1.0.0", "1.0.0")},
        {"native_capabilities": ("z.capability", "a.capability")},
        {
            "native_capabilities": ("market.data",),
            "approximated_capabilities": ("market.data",),
        },
        {
            "supported_operating_systems": (
                OperatingSystem.WINDOWS,
                OperatingSystem.LINUX,
            )
        },
        {"unexpected": "rejected"},
    ],
)
def test_descriptor_rejects_unsorted_duplicate_overlapping_or_unknown_values(
    updates: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _adapter(**updates)


def test_all_descriptor_arrays_are_explicit() -> None:
    payload = _adapter().model_dump(mode="python")
    for field in (
        "supported_protocol_versions",
        "supported_schema_versions",
        "native_capabilities",
        "approximated_capabilities",
        "unsupported_capabilities",
        "supported_operating_systems",
        "runtime_requirements",
        "known_modeling_limitations",
    ):
        missing = dict(payload)
        del missing[field]
        with pytest.raises(ValidationError, match="Field required"):
            AdapterDescriptor.model_validate(missing)


def test_engine_descriptor_rejects_unknown_and_unsorted_limitations() -> None:
    payload = _engine().model_dump(mode="python")
    payload["unexpected"] = True
    with pytest.raises(ValidationError, match="extra_forbidden"):
        EngineDescriptor.model_validate(payload)
    with pytest.raises(ValidationError, match="must be sorted"):
        EngineDescriptor(
            schema_version="1.0.0",
            engine_name="engine.alpha",
            engine_version="1.0.0",
            engine_family="engine.family",
            planned_role="Research.",
            known_limitations=("z", "a"),
        )


def test_descriptor_construction_launches_and_reads_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subprocess, "Popen", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(os, "getenv", _forbidden)
    _adapter()
```

Create `tests/unit/artifacts/test_ownership.py` with exactly:

```python
from __future__ import annotations

import pytest
from pydantic import ValidationError

from crypto_lab.artifacts.ownership import (
    ARTIFACT_OWNER_ADAPTER,
    AdapterArtifactOwner,
    DatasetArtifactOwner,
    ExperimentArtifactOwner,
    RunArtifactOwner,
    StrategyArtifactOwner,
    SystemArtifactOwner,
    artifact_owner_hash,
    owner_presentation,
)

_EXP = "exp_12345678-1234-4234-8234-123456789abc"
_RUN = "run_12345678-1234-4234-8234-123456789abc"
_DS = "ds_12345678-1234-4234-8234-123456789abc"
_STRV = "strv_12345678-1234-4234-8234-123456789abc"


def test_all_six_owner_variants_validate() -> None:
    owners = (
        RunArtifactOwner(
            owner_kind="RUN",
            experiment_id=_EXP,
            run_id=_RUN,
        ),
        ExperimentArtifactOwner(owner_kind="EXPERIMENT", experiment_id=_EXP),
        DatasetArtifactOwner(owner_kind="DATASET", dataset_id=_DS),
        StrategyArtifactOwner(
            owner_kind="STRATEGY",
            strategy_version_id=_STRV,
        ),
        AdapterArtifactOwner(
            owner_kind="ADAPTER",
            adapter_name="adapter.alpha",
            adapter_version="1.0.0",
        ),
        SystemArtifactOwner(
            owner_kind="SYSTEM",
            core_component="schema_registry",
            correlation_id="stage3",
        ),
    )
    for owner in owners:
        model_python = owner.model_dump(mode="python")
        model_json = owner.model_dump_json()
        adapter_python = ARTIFACT_OWNER_ADAPTER.dump_python(owner, mode="python")
        adapter_json = ARTIFACT_OWNER_ADAPTER.dump_json(owner)
        assert ARTIFACT_OWNER_ADAPTER.validate_python(model_python) == owner
        assert ARTIFACT_OWNER_ADAPTER.validate_json(model_json) == owner
        assert ARTIFACT_OWNER_ADAPTER.validate_python(adapter_python) == owner
        assert ARTIFACT_OWNER_ADAPTER.validate_json(adapter_json) == owner
        assert None not in model_python.values()
        assert "null" not in model_json
        assert None not in adapter_python.values()
        assert b"null" not in adapter_json


def test_owner_presentation_is_discriminator_first_and_omits_absent_fields() -> None:
    owner = RunArtifactOwner(
        owner_kind="RUN",
        experiment_id=_EXP,
        run_id=_RUN,
    )
    presentation = owner_presentation(owner)
    assert tuple(presentation) == ("owner_kind", "experiment_id", "run_id")
    assert "invocation_id" not in presentation


def test_system_owner_hash_matches_the_normative_golden() -> None:
    owner = SystemArtifactOwner(
        owner_kind="SYSTEM",
        core_component="schema_registry",
        correlation_id="stage3",
    )
    assert artifact_owner_hash(owner) == (
        "1ec94f41e62924c7715e7a6cd4c34cfa05af92060ecd7f05b8ebba580d213b11"
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"owner_kind": "STRATEGY"},
        {
            "owner_kind": "STRATEGY",
            "strategy_version_id": _STRV,
            "strategy_version_hash": "a" * 64,
        },
        {
            "owner_kind": "ADAPTER",
            "adapter_name": "adapter.alpha",
            "adapter_version": "1.0.0",
            "engine_name": "engine.alpha",
        },
        {
            "owner_kind": "RUN",
            "experiment_id": _EXP,
            "run_id": _RUN,
            "dataset_id": _DS,
        },
        {"owner_kind": "FOREIGN"},
    ],
)
def test_owner_union_rejects_invalid_cross_branch_combinations(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        ARTIFACT_OWNER_ADAPTER.validate_python(payload)


@pytest.mark.parametrize(
    "payload",
    [
        {
            "owner_kind": "RUN",
            "experiment_id": _EXP,
            "run_id": _RUN,
            "invocation_id": None,
        },
        {
            "owner_kind": "STRATEGY",
            "strategy_version_id": None,
            "strategy_version_hash": "a" * 64,
        },
        {
            "owner_kind": "ADAPTER",
            "adapter_name": "adapter.alpha",
            "adapter_version": "1.0.0",
            "engine_name": None,
        },
        {
            "owner_kind": "ADAPTER",
            "adapter_name": "adapter.alpha",
            "adapter_version": "1.0.0",
            "engine_version": None,
        },
    ],
)
def test_optional_owner_fields_reject_explicit_null(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        ARTIFACT_OWNER_ADAPTER.validate_python(payload)


def test_owner_is_frozen() -> None:
    owner = SystemArtifactOwner(
        owner_kind="SYSTEM",
        core_component="schema_registry",
        correlation_id="stage3",
    )
    with pytest.raises(ValidationError, match="frozen_instance"):
        owner.core_component = "other"
```

Create `tests/property/test_artifact_ownership.py` with exactly:

```python
from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from crypto_lab.artifacts.ownership import (
    ARTIFACT_OWNER_ADAPTER,
    AdapterArtifactOwner,
    StrategyArtifactOwner,
    SystemArtifactOwner,
    artifact_owner_hash,
)

_STRV = "strv_12345678-1234-4234-8234-123456789abc"


@given(has_id=st.booleans(), has_hash=st.booleans())
def test_strategy_owner_requires_exactly_one_identity(
    has_id: bool,
    has_hash: bool,
) -> None:
    payload: dict[str, object] = {"owner_kind": "STRATEGY"}
    if has_id:
        payload["strategy_version_id"] = _STRV
    if has_hash:
        payload["strategy_version_hash"] = "a" * 64
    if has_id != has_hash:
        owner = ARTIFACT_OWNER_ADAPTER.validate_python(payload)
        assert isinstance(owner, StrategyArtifactOwner)
    else:
        with pytest.raises(ValidationError):
            ARTIFACT_OWNER_ADAPTER.validate_python(payload)


@given(
    has_engine_name=st.booleans(),
    has_engine_version=st.booleans(),
    null_name=st.booleans(),
    null_version=st.booleans(),
)
def test_adapter_engine_fields_are_all_or_none_and_never_null(
    has_engine_name: bool,
    has_engine_version: bool,
    null_name: bool,
    null_version: bool,
) -> None:
    payload: dict[str, object] = {
        "owner_kind": "ADAPTER",
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
    }
    if has_engine_name:
        payload["engine_name"] = None if null_name else "engine.alpha"
    if has_engine_version:
        payload["engine_version"] = None if null_version else "1.0.0"
    valid = (not has_engine_name and not has_engine_version) or (
        has_engine_name and has_engine_version and not null_name and not null_version
    )
    if valid:
        owner = ARTIFACT_OWNER_ADAPTER.validate_python(payload)
        assert isinstance(owner, AdapterArtifactOwner)
    else:
        with pytest.raises(ValidationError):
            ARTIFACT_OWNER_ADAPTER.validate_python(payload)


@given(
    component=st.from_regex(r"[a-z][a-z0-9]{0,15}", fullmatch=True),
    correlation=st.from_regex(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,31}",
        fullmatch=True,
    ),
)
def test_owner_hash_is_deterministic(
    component: str,
    correlation: str,
) -> None:
    owner = SystemArtifactOwner(
        owner_kind="SYSTEM",
        core_component=component,
        correlation_id=correlation,
    )
    assert artifact_owner_hash(owner) == artifact_owner_hash(owner)


@given(
    kind=st.sampled_from(
        ("RUN", "EXPERIMENT", "DATASET", "STRATEGY", "ADAPTER", "SYSTEM")
    ),
    foreign_field=st.sampled_from(
        ("artifact_id", "candidate_artifact_id", "event_id", "audit_event_id")
    ),
)
def test_every_selected_branch_rejects_foreign_fields(
    kind: str,
    foreign_field: str,
) -> None:
    payloads: dict[str, dict[str, object]] = {
        "RUN": {
            "owner_kind": "RUN",
            "experiment_id": "exp_12345678-1234-4234-8234-123456789abc",
            "run_id": "run_12345678-1234-4234-8234-123456789abc",
        },
        "EXPERIMENT": {
            "owner_kind": "EXPERIMENT",
            "experiment_id": "exp_12345678-1234-4234-8234-123456789abc",
        },
        "DATASET": {
            "owner_kind": "DATASET",
            "dataset_id": "ds_12345678-1234-4234-8234-123456789abc",
        },
        "STRATEGY": {
            "owner_kind": "STRATEGY",
            "strategy_version_id": _STRV,
        },
        "ADAPTER": {
            "owner_kind": "ADAPTER",
            "adapter_name": "adapter.alpha",
            "adapter_version": "1.0.0",
        },
        "SYSTEM": {
            "owner_kind": "SYSTEM",
            "core_component": "schema_registry",
            "correlation_id": "stage3",
        },
    }
    payload = dict(payloads[kind])
    payload[foreign_field] = "foreign"
    with pytest.raises(ValidationError):
        ARTIFACT_OWNER_ADAPTER.validate_python(payload)
```

---

### A.12 Exact schema and distribution test files

Create `tests/unit/test_schema_registry.py` with exactly:

```python
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from scripts.generate_schemas import _check, _write

from crypto_lab.schema_registry import (
    JSON_SCHEMA_DRAFT,
    SCHEMA_DEFINITIONS,
    render_schema_files,
)

_EXPECTED = {
    PurePosixPath(
        "domain/instrument-ref-v1.schema.json"
    ): "urn:crypto-lab:schema:domain:instrument-ref:1.0.0",
    PurePosixPath(
        "domain/money-v1.schema.json"
    ): "urn:crypto-lab:schema:domain:money:1.0.0",
    PurePosixPath(
        "domain/price-v1.schema.json"
    ): "urn:crypto-lab:schema:domain:price:1.0.0",
    PurePosixPath(
        "domain/quantity-v1.schema.json"
    ): "urn:crypto-lab:schema:domain:quantity:1.0.0",
    PurePosixPath(
        "domain/diagnostic-v1.schema.json"
    ): "urn:crypto-lab:schema:domain:diagnostic:1.0.0",
    PurePosixPath(
        "configuration/application-config-v1.schema.json"
    ): "urn:crypto-lab:schema:configuration:application-config:1.0.0",
    PurePosixPath(
        "datasets/dataset-partition-v1.schema.json"
    ): "urn:crypto-lab:schema:datasets:dataset-partition:1.0.0",
    PurePosixPath(
        "datasets/dataset-descriptor-v1.schema.json"
    ): "urn:crypto-lab:schema:datasets:dataset-descriptor:1.0.0",
    PurePosixPath(
        "protocol/engine-descriptor-v1.schema.json"
    ): "urn:crypto-lab:schema:protocol:engine-descriptor:1.0.0",
    PurePosixPath(
        "protocol/adapter-descriptor-v1.schema.json"
    ): "urn:crypto-lab:schema:protocol:adapter-descriptor:1.0.0",
    PurePosixPath(
        "artifacts/artifact-owner-ref-v1.schema.json"
    ): "urn:crypto-lab:schema:artifacts:artifact-owner-ref:1.0.0",
}


def _schemas() -> dict[PurePosixPath, dict[str, Any]]:
    return {
        path: cast(dict[str, Any], json.loads(contents))
        for path, contents in render_schema_files().items()
    }


def _references(value: object) -> tuple[str, ...]:
    if isinstance(value, dict):
        direct = (value["$ref"],) if isinstance(value.get("$ref"), str) else ()
        return direct + tuple(
            reference for nested in value.values() for reference in _references(nested)
        )
    if isinstance(value, list):
        return tuple(reference for nested in value for reference in _references(nested))
    return ()


def _patterns(value: object) -> tuple[str, ...]:
    if isinstance(value, dict):
        direct = (value["pattern"],) if isinstance(value.get("pattern"), str) else ()
        return direct + tuple(
            pattern for nested in value.values() for pattern in _patterns(nested)
        )
    if isinstance(value, list):
        return tuple(pattern for nested in value for pattern in _patterns(nested))
    return ()


def _resolve_local_ref(
    document: dict[str, Any],
    node: dict[str, Any],
) -> dict[str, Any]:
    resolved = node
    seen: set[str] = set()
    while isinstance(resolved.get("$ref"), str):
        reference = cast(str, resolved["$ref"])
        if not reference.startswith("#/") or reference in seen:
            raise AssertionError(f"invalid local schema reference: {reference}")
        seen.add(reference)
        target: object = document
        for token in reference.removeprefix("#/").split("/"):
            if not isinstance(target, dict):
                raise AssertionError(f"unresolvable schema reference: {reference}")
            target = target[token.replace("~1", "/").replace("~0", "~")]
        if not isinstance(target, dict):
            raise AssertionError(f"schema reference is not an object: {reference}")
        resolved = cast(dict[str, Any], target)
    return resolved


def test_registry_has_exactly_the_closed_eleven_paths_and_ids() -> None:
    assert {
        definition.relative_path: definition.schema_id
        for definition in SCHEMA_DEFINITIONS
    } == _EXPECTED
    assert len(SCHEMA_DEFINITIONS) == 11


def test_every_schema_is_deterministic_draft_2020_12() -> None:
    first = render_schema_files()
    assert render_schema_files() == first
    assert set(first) == set(_EXPECTED)
    for path, contents in first.items():
        assert contents.endswith(b"\n")
        assert not contents.endswith(b"\n\n")
        schema = cast(dict[str, Any], json.loads(contents))
        assert schema["$schema"] == JSON_SCHEMA_DRAFT
        assert schema["$id"] == _EXPECTED[path]
        Draft202012Validator.check_schema(schema)


def test_every_schema_reference_is_document_local() -> None:
    for schema in _schemas().values():
        assert all(reference.startswith("#/") for reference in _references(schema))


def test_every_schema_pattern_uses_absolute_end_semantics() -> None:
    patterns = tuple(
        pattern for schema in _schemas().values() for pattern in _patterns(schema)
    )
    assert patterns
    assert all(not pattern.endswith("$") for pattern in patterns)


@pytest.mark.parametrize(
    ("path", "field"),
    [
        (PurePosixPath("domain/money-v1.schema.json"), "amount"),
        (PurePosixPath("domain/price-v1.schema.json"), "value"),
        (PurePosixPath("domain/quantity-v1.schema.json"), "value"),
    ],
)
def test_decimal_schema_fields_are_string_only(
    path: PurePosixPath,
    field: str,
) -> None:
    document = _schemas()[path]
    field_schema = _resolve_local_ref(document, document["properties"][field])
    assert field_schema["type"] == "string"
    assert "pattern" in field_schema
    assert "maxLength" in field_schema


def test_diagnostic_schema_compiles_signed_64_bit_detail_bounds() -> None:
    schema = _schemas()[PurePosixPath("domain/diagnostic-v1.schema.json")]
    validator = Draft202012Validator(schema)
    document = {
        "schema_version": "1.0.0",
        "diagnostic_id": "diag_12345678-1234-4234-8234-123456789abc",
        "severity": "ERROR",
        "error_code": "CONFIG.LAYER_INVALID",
        "category": "USER_CONFIGURATION",
        "message": "Configuration layer is invalid.",
        "source_component": "configuration.loader",
        "retriable": False,
        "timestamp_utc": "2026-08-10T00:00:00Z",
        "details": {"count": 0},
        "causal_diagnostic_ids": [],
    }
    for boundary in (-(2**63), 2**63 - 1):
        validator.validate({**document, "details": {"count": boundary}})
    for invalid in (-(2**63) - 1, 2**63, 0.5):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate({**document, "details": {"count": invalid}})
    for error_code in ("invalid", "CONFIG", "CONFIG.bad"):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate({**document, "error_code": error_code})
    invalid_details = (
        {"message": "x" * 2049},
        {"items": list(range(65))},
        {f"key{index}": index for index in range(65)},
        {"x" * 129: "value"},
    )
    for details in invalid_details:
        with pytest.raises(JsonSchemaValidationError):
            validator.validate({**document, "details": details})
    for field in ("experiment_id", "run_id", "invocation_id", "engine"):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate({**document, field: None})
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(
            {
                **document,
                "run_id": "run_12345678-1234-4234-8234-123456789abc",
            }
        )
    with pytest.raises(JsonSchemaValidationError):
        validator.validate({**document, "category": "ENGINE_RUNTIME"})
    validator.validate(
        {
            **document,
            "category": "ENGINE_RUNTIME",
            "invocation_id": "inv_12345678-1234-4234-8234-123456789abc",
        }
    )
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(
            {
                **document,
                "causal_diagnostic_ids": [
                    "diag_22345678-1234-4234-8234-123456789abc",
                    "diag_22345678-1234-4234-8234-123456789abc",
                ],
            }
        )


def test_configuration_schema_compiles_local_windows_path_rules() -> None:
    schema = _schemas()[
        PurePosixPath("configuration/application-config-v1.schema.json")
    ]
    validator = Draft202012Validator(schema)
    validator.validate({"paths": {"runtime_root": "safe/root"}})
    validator.validate({"paths": {"runtime_root": r"C:\safe\root"}})
    for invalid in (
        r"C:drive-relative",
        r"\rooted-without-drive",
        r"\\server\share",
        "folder/../escape",
        "folder/name:stream",
        "folder/CON",
        "folder/bad?name",
        "folder/control\x1f",
        "folder/trailing.",
    ):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate({"paths": {"runtime_root": invalid}})
    validator.validate({"database": {"filename": "crypto_lab.sqlite3"}})
    for filename in ("CON", "aux.db", "trailing.", "trailing ", "bad?.db"):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate({"database": {"filename": filename}})
    entry = {
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "executable_path": r"C:\adapters\adapter.exe",
        "executable_hash": "a" * 64,
        "runtime_metadata": {},
    }
    validator.validate({"adapters": {"entries": [entry]}})
    with pytest.raises(JsonSchemaValidationError):
        validator.validate({"adapters": {"entries": [entry, entry]}})
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(
            {
                "scheduler": {
                    "retry": {
                        "automatically_retry_terminal_states": [
                            "FAILED",
                            "FAILED",
                        ]
                    }
                }
            }
        )
    invalid_entries = (
        {**entry, "executable_path": "relative.exe"},
        {**entry, "runtime_metadata": {"count": 2**63}},
        {**entry, "runtime_metadata": {"count": -(2**63) - 1}},
        {**entry, "runtime_metadata": {"ratio": 0.5}},
        {**entry, "runtime_metadata": {"text": "x" * 2049}},
        {**entry, "runtime_metadata": {"items": list(range(65))}},
        {
            **entry,
            "runtime_metadata": {f"key{index}": index for index in range(65)},
        },
        {**entry, "runtime_metadata": {"x" * 129: "value"}},
    )
    for invalid_entry in invalid_entries:
        with pytest.raises(JsonSchemaValidationError):
            validator.validate({"adapters": {"entries": [invalid_entry]}})


def test_utc_and_structured_schema_version_shapes_are_explicit() -> None:
    schemas = _schemas()
    partition = schemas[PurePosixPath("datasets/dataset-partition-v1.schema.json")]
    start_utc = _resolve_local_ref(partition, partition["properties"]["start_utc"])
    assert start_utc["pattern"].endswith(r"Z(?![\s\S])")
    validator = Draft202012Validator(start_utc)
    validator.validate("2026-08-10T00:00:00Z")
    for terminator in ("\n", "\r", "\r\n"):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate("2026-08-10T00:00:00Z" + terminator)
    adapter = schemas[PurePosixPath("protocol/adapter-descriptor-v1.schema.json")]
    supported = adapter["properties"]["supported_schema_versions"]
    assert supported["type"] == "array"
    assert "SupportedSchemaVersion" in supported["items"]["$ref"]


def test_dataset_partition_schema_enforces_safe_registry_relative_paths() -> None:
    schema = _schemas()[PurePosixPath("datasets/dataset-partition-v1.schema.json")]
    validator = Draft202012Validator(schema)
    provenance = {
        "source_name": "fixture.source",
        "source_version": "1.0.0",
        "source_record": "fixture",
        "source_hash": "3" * 64,
    }
    document = {
        "schema_version": "1.0.0",
        "partition_id": "part_12345678-1234-4234-8234-123456789abc",
        "dataset_id": "ds_12345678-1234-4234-8234-123456789abc",
        "ordinal": 0,
        "relative_path": "ohlcv/part.parquet",
        "content_hash": "0" * 64,
        "row_count": 1,
        "start_utc": "2026-01-01T00:00:00Z",
        "end_utc": "2026-01-02T00:00:00Z",
        "raw_checksum": "1" * 64,
        "normalized_checksum": "2" * 64,
        "column_schema_version": "1.0.0",
        "raw_source_provenance": [provenance],
        "quality_observations": [],
    }
    validator.validate(document)
    for path in (
        "/root/file",
        "//server/share",
        r"folder\file",
        "C:/file",
        "file:stream",
        "../file",
        "folder//file",
        "folder/AUX.txt",
        "folder/control\x1f",
        "folder/trailing.",
        "folder/trailing ",
    ):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate({**document, "relative_path": path})
    for invalid in (
        {**document, "row_count": 0},
        {
            **document,
            "raw_source_provenance": [provenance, provenance],
        },
        {**document, "quality_observations": ["duplicate", "duplicate"]},
    ):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate(invalid)
    validator.validate({**document, "row_count": 0, "quality_observations": ["empty"]})


def test_dataset_descriptor_schema_matches_expressible_runtime_invariants() -> None:
    schema = _schemas()[PurePosixPath("datasets/dataset-descriptor-v1.schema.json")]
    validator = Draft202012Validator(schema)
    provenance = {
        "source_name": "fixture.source",
        "source_version": "1.0.0",
        "source_record": "fixture",
        "source_hash": "3" * 64,
    }
    interval = {
        "start_utc": "2026-01-01T00:00:00Z",
        "end_utc": "2026-01-02T00:00:00Z",
    }
    diagnostic_id = "diag_12345678-1234-4234-8234-123456789abc"
    document = {
        "schema_version": "1.0.0",
        "dataset_id": "ds_12345678-1234-4234-8234-123456789abc",
        "content_hash": "0" * 64,
        "source": "fixture",
        "venue": "BINANCE",
        "instrument": {
            "schema_version": "1.0.0",
            "canonical_id": "BINANCE:BTC/USDT:SPOT",
            "venue": "BINANCE",
            "base_asset": "BTC",
            "quote_asset": "USDT",
            "market_type": "SPOT",
        },
        "data_type": "OHLCV",
        "timeframe": "1m",
        "start_utc": "2026-01-01T00:00:00Z",
        "end_utc": "2026-01-02T00:00:00Z",
        "original_timezone": "UTC",
        "normalized_to_utc": True,
        "raw_source_provenance": [provenance],
        "normalization_implementation": "fixture.normalizer",
        "normalization_version": "1.0.0",
        "validation_status": "VALID",
        "partition_ids": ["part_12345678-1234-4234-8234-123456789abc"],
        "missing_intervals": [],
        "duplicate_intervals": [],
        "diagnostic_ids": [],
        "raw_checksums": ["1" * 64],
        "normalized_checksums": ["2" * 64],
        "column_schema_version": "1.0.0",
        "known_limitations": [],
        "created_at_utc": "2026-01-02T00:00:00Z",
    }
    validator.validate(document)
    invalid_documents = (
        {key: value for key, value in document.items() if key != "timeframe"},
        {**document, "data_type": "TRADES"},
        {**document, "timeframe": None},
        {**document, "imported_at_utc": None},
        {**document, "partition_ids": document["partition_ids"] * 2},
        {**document, "raw_source_provenance": [provenance, provenance]},
        {**document, "known_limitations": ["same", "same"]},
        {**document, "validation_status": "VALID", "missing_intervals": [interval]},
        {**document, "validation_status": "VALID_WITH_WARNINGS"},
        {**document, "validation_status": "INVALID"},
        {
            **document,
            "validation_status": "VALID_WITH_WARNINGS",
            "diagnostic_ids": [diagnostic_id, diagnostic_id],
        },
    )
    for invalid in invalid_documents:
        with pytest.raises(JsonSchemaValidationError):
            validator.validate(invalid)
    trades = {**document, "data_type": "TRADES"}
    del trades["timeframe"]
    validator.validate(trades)
    validator.validate(
        {
            **document,
            "validation_status": "VALID_WITH_WARNINGS",
            "missing_intervals": [interval],
        }
    )
    validator.validate(
        {
            **document,
            "validation_status": "INVALID",
            "diagnostic_ids": [diagnostic_id],
        }
    )


def test_descriptor_schemas_reject_duplicate_collection_items() -> None:
    schemas = _schemas()
    engine = {
        "schema_version": "1.0.0",
        "engine_name": "engine.alpha",
        "engine_version": "1.0.0",
        "engine_family": "engine.alpha",
        "planned_role": "structural fixture",
        "known_limitations": [],
    }
    engine_validator = Draft202012Validator(
        schemas[PurePosixPath("protocol/engine-descriptor-v1.schema.json")]
    )
    engine_validator.validate(engine)
    with pytest.raises(JsonSchemaValidationError):
        engine_validator.validate({**engine, "known_limitations": ["same", "same"]})
    schema_version = {"schema_name": "domain.money", "schema_version": "1.0.0"}
    adapter = {
        "schema_version": "1.0.0",
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "engine": engine,
        "supported_protocol_versions": ["1.0.0"],
        "supported_schema_versions": [schema_version],
        "capability_vocabulary_version": "capabilities/v1",
        "native_capabilities": ["market.data"],
        "approximated_capabilities": [],
        "unsupported_capabilities": [],
        "supported_operating_systems": ["WINDOWS"],
        "runtime_requirements": [],
        "network_required": False,
        "credentials_required": False,
        "known_modeling_limitations": [],
        "executable_hash": "a" * 64,
    }
    adapter_validator = Draft202012Validator(
        schemas[PurePosixPath("protocol/adapter-descriptor-v1.schema.json")]
    )
    adapter_validator.validate(adapter)
    duplicate_values: dict[str, object] = {
        "supported_protocol_versions": ["1.0.0", "1.0.0"],
        "supported_schema_versions": [schema_version, schema_version],
        "native_capabilities": ["market.data", "market.data"],
        "supported_operating_systems": ["WINDOWS", "WINDOWS"],
        "runtime_requirements": ["same", "same"],
        "known_modeling_limitations": ["same", "same"],
    }
    for field, duplicate in duplicate_values.items():
        with pytest.raises(JsonSchemaValidationError):
            adapter_validator.validate({**adapter, field: duplicate})


def test_owner_schema_has_all_six_discriminated_branches() -> None:
    schema = _schemas()[PurePosixPath("artifacts/artifact-owner-ref-v1.schema.json")]
    schema_text = json.dumps(schema, sort_keys=True)
    assert '"null"' not in schema_text
    assert '"default": null' not in schema_text
    assert len(schema["oneOf"]) == 6
    assert set(schema["discriminator"]["mapping"]) == {
        "RUN",
        "EXPERIMENT",
        "DATASET",
        "STRATEGY",
        "ADAPTER",
        "SYSTEM",
    }
    documents = [
        {
            "owner_kind": "RUN",
            "experiment_id": "exp_12345678-1234-4234-8234-123456789abc",
            "run_id": "run_12345678-1234-4234-8234-123456789abc",
        },
        {
            "owner_kind": "EXPERIMENT",
            "experiment_id": "exp_12345678-1234-4234-8234-123456789abc",
        },
        {
            "owner_kind": "DATASET",
            "dataset_id": "ds_12345678-1234-4234-8234-123456789abc",
        },
        {"owner_kind": "STRATEGY", "strategy_version_hash": "a" * 64},
        {
            "owner_kind": "ADAPTER",
            "adapter_name": "adapter.alpha",
            "adapter_version": "1.0.0",
        },
        {
            "owner_kind": "SYSTEM",
            "core_component": "schema_registry",
            "correlation_id": "stage3",
        },
    ]
    validator = Draft202012Validator(schema)
    for document in documents:
        validator.validate(document)
    with pytest.raises(JsonSchemaValidationError):
        validator.validate({**documents[-1], "unexpected": True})
    explicit_null_documents = [
        {**documents[0], "invocation_id": None},
        {
            "owner_kind": "STRATEGY",
            "strategy_version_id": None,
            "strategy_version_hash": "a" * 64,
        },
        {**documents[4], "engine_name": None},
        {**documents[4], "engine_version": None},
    ]
    for invalid_document in explicit_null_documents:
        with pytest.raises(JsonSchemaValidationError):
            validator.validate(invalid_document)
    conditional_failures = [
        {"owner_kind": "STRATEGY"},
        {
            "owner_kind": "STRATEGY",
            "strategy_version_id": "strv_12345678-1234-4234-8234-123456789abc",
            "strategy_version_hash": "a" * 64,
        },
        {**documents[4], "engine_name": "engine.alpha"},
        {**documents[4], "engine_version": "1.0.0"},
    ]
    for invalid_document in conditional_failures:
        with pytest.raises(JsonSchemaValidationError):
            validator.validate(invalid_document)


def test_instrument_schema_rejects_extra_fields() -> None:
    schema = _schemas()[PurePosixPath("domain/instrument-ref-v1.schema.json")]
    validator = Draft202012Validator(schema)
    document = {
        "schema_version": "1.0.0",
        "canonical_id": "BINANCE:BTC/USDT:SPOT",
        "venue": "BINANCE",
        "base_asset": "BTC",
        "quote_asset": "USDT",
        "market_type": "SPOT",
    }
    validator.validate(document)
    with pytest.raises(JsonSchemaValidationError):
        validator.validate({**document, "unexpected": True})


def test_generator_detects_missing_changed_and_unexpected_files(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected = render_schema_files()
    assert _write(tmp_path, expected) == 0
    assert _check(tmp_path, expected) == 0
    first_path = next(iter(expected))
    target = tmp_path.joinpath(*first_path.parts)
    target.write_bytes(b"changed\n")
    assert _check(tmp_path, expected) == 1
    assert "changed schema" in capsys.readouterr().err
    target.unlink()
    assert _check(tmp_path, expected) == 1
    assert "missing schema" in capsys.readouterr().err
    assert _write(tmp_path, expected) == 0
    (tmp_path / "foreign.schema.json").write_text("{}\n", encoding="utf-8")
    assert _check(tmp_path, expected) == 1
    assert "unexpected schema" in capsys.readouterr().err
    assert _write(tmp_path, expected) == 1
    assert (tmp_path / "foreign.schema.json").is_file()


def test_generator_rejects_symlinked_entries_without_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = render_schema_files()
    assert _write(tmp_path, expected) == 0
    target = tmp_path.joinpath(*next(iter(expected)).parts)
    original = Path.is_symlink

    def _reported_symlink(path: Path) -> bool:
        return path == target or original(path)

    monkeypatch.setattr(Path, "is_symlink", _reported_symlink)
    with pytest.raises(ValueError, match="must not be a symlink"):
        _write(tmp_path, expected)
```

Create `tests/integration/test_schema_distribution.py` with exactly:

```python
from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Literal

import pytest
from scripts.verify_schema_distribution import (
    _single,
    _verify_sdist,
    _verify_source,
    _verify_wheel,
    main,
)

from crypto_lab.schema_registry import render_schema_files

type Variant = Literal[
    "exact",
    "missing",
    "changed",
    "duplicate",
    "unexpected",
    "unexpected_payload",
    "backslash",
    "special",
    "schema_root_symlink",
    "schema_root_file",
]


def _write_source(
    root: Path,
    expected: dict[PurePosixPath, bytes],
) -> None:
    for relative_path, contents in expected.items():
        target = root.joinpath(*relative_path.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(contents)


def _write_wheel(
    path: Path,
    expected: dict[PurePosixPath, bytes],
    *,
    variant: Variant = "exact",
    prefix: str = "crypto_lab/schemas",
) -> None:
    with zipfile.ZipFile(path, mode="w") as archive:
        if variant in {"schema_root_symlink", "schema_root_file"}:
            root = zipfile.ZipInfo("crypto_lab/schemas/")
            root.create_system = 3
            root.external_attr = (
                0o120777 if variant == "schema_root_symlink" else 0o100644
            ) << 16
            archive.writestr(
                root, b"target" if variant == "schema_root_symlink" else b""
            )
        for index, (relative_path, contents) in enumerate(expected.items()):
            if index == 0 and variant == "missing":
                continue
            name = f"{prefix}/{relative_path.as_posix()}"
            written = b"changed\n" if index == 0 and variant == "changed" else contents
            archive.writestr(name, written)
            if index == 0 and variant == "duplicate":
                archive.writestr(name, written)
        if variant == "unexpected":
            archive.writestr(f"{prefix}/foreign.schema.json", b"{}\n")
        if variant == "unexpected_payload":
            archive.writestr(f"{prefix}/README.txt", b"foreign\n")
        if variant == "backslash":
            archive.writestr(f"{prefix}\\README.txt", b"foreign\n")


def _add_tar_member(
    archive: tarfile.TarFile,
    name: str,
    contents: bytes,
) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(contents)
    archive.addfile(info, io.BytesIO(contents))


def _add_tar_special(archive: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.FIFOTYPE
    archive.addfile(info)


def _write_sdist(
    path: Path,
    expected: dict[PurePosixPath, bytes],
    *,
    variant: Variant = "exact",
    archive_root: str | None = None,
) -> None:
    root = path.name.removesuffix(".tar.gz") if archive_root is None else archive_root
    with tarfile.open(path, mode="w:gz") as archive:
        root_info = tarfile.TarInfo(f"{root}/schemas")
        if variant == "schema_root_symlink":
            root_info.type = tarfile.SYMTYPE
            root_info.linkname = "elsewhere"
        elif variant == "schema_root_file":
            root_info.type = tarfile.REGTYPE
        else:
            root_info.type = tarfile.DIRTYPE
        archive.addfile(root_info)
        for index, (relative_path, contents) in enumerate(expected.items()):
            if index == 0 and variant == "missing":
                continue
            name = f"{root}/schemas/{relative_path.as_posix()}"
            written = b"changed\n" if index == 0 and variant == "changed" else contents
            _add_tar_member(archive, name, written)
            if index == 0 and variant == "duplicate":
                _add_tar_member(archive, name, written)
        if variant == "unexpected":
            _add_tar_member(
                archive,
                f"{root}/schemas/foreign.schema.json",
                b"{}\n",
            )
        if variant == "unexpected_payload":
            _add_tar_member(
                archive,
                f"{root}/schemas/README.txt",
                b"foreign\n",
            )
        if variant == "backslash":
            _add_tar_member(archive, f"{root}\\schemas\\README.txt", b"foreign\n")
        if variant == "special":
            _add_tar_special(archive, f"{root}/schemas/pipe")


def test_source_wheel_and_sdist_helpers_accept_exact_bytes(
    tmp_path: Path,
) -> None:
    expected = render_schema_files()
    source = tmp_path / "schemas"
    wheel = tmp_path / "package.whl"
    sdist = tmp_path / "crypto_trading_lab-0.1.0.tar.gz"
    _write_source(source, expected)
    _write_wheel(wheel, expected)
    _write_sdist(sdist, expected)
    _verify_source(source, expected)
    _verify_wheel(wheel, expected)
    _verify_sdist(sdist, expected)


@pytest.mark.parametrize(
    "variant",
    [
        "missing",
        "changed",
        "unexpected",
        "unexpected_payload",
        "backslash",
        "schema_root_symlink",
        "schema_root_file",
    ],
)
def test_wheel_rejects_missing_changed_and_unexpected_entries(
    tmp_path: Path,
    variant: Variant,
) -> None:
    expected = render_schema_files()
    wheel = tmp_path / "package.whl"
    _write_wheel(wheel, expected, variant=variant)
    with pytest.raises(ValueError, match="wheel"):
        _verify_wheel(wheel, expected)


def test_wheel_rejects_duplicate_and_root_level_entries(
    tmp_path: Path,
) -> None:
    expected = render_schema_files()
    duplicate = tmp_path / "duplicate.whl"
    with pytest.warns(UserWarning, match=r"Duplicate name:"):
        _write_wheel(duplicate, expected, variant="duplicate")
    with pytest.raises(ValueError, match="duplicated"):
        _verify_wheel(duplicate, expected)
    root_level = tmp_path / "root.whl"
    _write_wheel(root_level, expected, prefix="schemas")
    with pytest.raises(ValueError, match="wheel schema"):
        _verify_wheel(root_level, expected)


@pytest.mark.parametrize(
    "variant",
    [
        "missing",
        "changed",
        "duplicate",
        "unexpected",
        "unexpected_payload",
        "backslash",
        "special",
        "schema_root_symlink",
        "schema_root_file",
    ],
)
def test_sdist_rejects_missing_changed_duplicate_and_unexpected_entries(
    tmp_path: Path,
    variant: Variant,
) -> None:
    expected = render_schema_files()
    sdist = tmp_path / "crypto_trading_lab-0.1.0.tar.gz"
    _write_sdist(sdist, expected, variant=variant)
    with pytest.raises(ValueError, match="sdist"):
        _verify_sdist(sdist, expected)


def test_sdist_root_is_derived_exactly_from_the_archive_filename(
    tmp_path: Path,
) -> None:
    expected = render_schema_files()
    sdist = tmp_path / "crypto_trading_lab-0.1.0.tar.gz"
    _write_sdist(sdist, expected, archive_root="wrong-root")
    with pytest.raises(ValueError, match="sdist schema"):
        _verify_sdist(sdist, expected)


def test_source_and_single_helpers_reject_mismatches(tmp_path: Path) -> None:
    expected = render_schema_files()
    source = tmp_path / "schemas"
    _write_source(source, expected)
    first = next(iter(expected))
    source.joinpath(*first.parts).write_bytes(b"changed\n")
    with pytest.raises(ValueError, match="source schema tree"):
        _verify_source(source, expected)
    _write_source(source, expected)
    (source / "README.txt").write_text("foreign\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source schema tree"):
        _verify_source(source, expected)
    wheel = tmp_path / "one.whl"
    assert _single([wheel], "wheel") == wheel
    with pytest.raises(ValueError, match="exactly one wheel"):
        _single([], "wheel")
    with pytest.raises(ValueError, match="exactly one wheel"):
        _single([wheel, tmp_path / "two.whl"], "wheel")


def test_distribution_main_accepts_one_exact_pair(tmp_path: Path) -> None:
    expected = render_schema_files()
    source = tmp_path / "schemas"
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_source(source, expected)
    _write_wheel(dist / "package.whl", expected)
    _write_sdist(dist / "crypto_trading_lab-0.1.0.tar.gz", expected)
    assert main(("--source", str(source), "--dist", str(dist))) == 0


def test_distribution_main_rejects_multiple_archives(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected = render_schema_files()
    source = tmp_path / "schemas"
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_source(source, expected)
    _write_wheel(dist / "one.whl", expected)
    _write_wheel(dist / "two.whl", expected)
    _write_sdist(dist / "crypto_trading_lab-0.1.0.tar.gz", expected)
    assert main(("--source", str(source), "--dist", str(dist))) == 1
    assert "expected exactly one wheel" in capsys.readouterr().err
```

### A.13 Exact Task 9 roadmap and README status patch

Apply this exact patch to
`docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md` in Task 9. Before
calling `apply_patch`, replace both occurrences of
`__STAGE3_IMPLEMENTATION_COMMIT__`—one here and one in the exact A.8 test
constant—with the same captured lowercase 40-character
`$stage3ImplementationCommit`. No binding token may remain in a staged file.

```diff
@@
-**Status:** Approved planning decomposition; Stages 1 and 2 complete
+**Status:** Approved planning decomposition; Stages 1 through 3 complete
@@
-Stages 1 and 2 have approved detailed implementation plans. Every later detailed plan is written just in time after its prerequisite implementation is complete, verified, reviewed, and committed.
+Stages 1 through 3 have approved detailed implementation plans. Every later detailed plan is written just in time after its prerequisite implementation is complete, verified, reviewed, and committed.
@@
-**Planned detailed implementation plan:** `docs/superpowers/plans/2026-08-10-project-1-canonical-domain-configuration-hashing-schemas-implementation-plan.md`.
+**Approved detailed implementation plan:** `docs/superpowers/plans/2026-08-10-project-1-canonical-domain-configuration-hashing-schemas-implementation-plan.md`.
@@
-| 3 — Canonical Domain, Configuration, Hashing, and Schemas | Eligible for just-in-time planning after the completed Stage 2 governance decision | Not started | Not evaluated |
-| 4 — Portable Strategy, Capabilities, and Comparison | Intentionally deferred until Stage 3 completion | Not started | Not evaluated |
+| 3 — Canonical Domain, Configuration, Hashing, and Schemas | Approved and executed | Complete at `__STAGE3_IMPLEMENTATION_COMMIT__` | Complete; canonical models, explicit configuration, named hashes, dataset metadata, structural descriptors, artifact owners, and 11 generated schemas verified offline |
+| 4 — Portable Strategy, Capabilities, and Comparison | Eligible for just-in-time planning after Stage 3 completion | Not started | Not evaluated |
```

Apply this exact Task 9 patch to `README.md` after the Task 8 patch in A.7:

```diff
@@
-**Status:** Project 1 Stage 3 implementation under acceptance review
+**Status:** Project 1 Stages 1-3 complete
@@
-Crypto Trading Lab is a personal, local-only Windows project for building an engine-neutral research and simulated-trading foundation. Stage 1 supplies the Python scaffold and offline workflow; Stage 2 records GitNexus as `DISABLED_WITH_EVIDENCE`; Stage 3 adds strict canonical values, explicit configuration, deterministic hashes, dataset metadata, structural descriptors, artifact ownership, and generated schemas without adding an engine or runtime service.
+Crypto Trading Lab is a personal, local-only Windows project for building an engine-neutral research and simulated-trading foundation. Stage 1 supplies the Python scaffold and offline workflow; Stage 2 records GitNexus as `DISABLED_WITH_EVIDENCE`; Stage 3 completes the strict canonical-value, explicit-configuration, deterministic-hashing, dataset-metadata, structural-descriptor, artifact-ownership, and generated-schema foundation without adding an engine or runtime service.
```

After applying both status patches and the A.8 test binding, run:

```powershell
if ($stage3ImplementationCommit -notmatch '^[0-9a-f]{40}$') {
    throw "Stage 3 implementation commit must be a lowercase 40-character hash"
}
rg -n "__STAGE3_IMPLEMENTATION_COMMIT__" `
  docs\superpowers\plans\2026-08-10-project-1-master-roadmap.md `
  tests\safety\test_stage3_boundaries.py
if ($LASTEXITCODE -ne 1) {
    throw "Stage 3 implementation commit binding is incomplete"
}
```

Required: `rg` exits 1 with no output because the runtime binding token was
fully replaced. This check makes the future commit value executable without
leaving an unresolved design decision in the plan.

---

## Plan self-review

This is a review of the executable plan, not a claim that Stage 3 has run:

- [x] Tasks 1 through 9 are physically ordered by dependency. Task 9 performs
  the roadmap/README completion update only after Task 8's fresh full verifier
  succeeds and its implementation commit is captured.
- [x] The closed file map has 68 paths: 56 text paths with literal complete
  contents or exact patches, `uv.lock` generated only by uv, and 11 schema
  files generated only from the closed deterministic registry.
- [x] The registry has exactly 11 unique paths and stable URN IDs. Descriptor
  schemas are under `schemas/protocol`; no semantic-version or owner-wrapper
  schema was invented; every `$ref` is recursively checked as local-only.
- [x] Runtime dependencies are limited to Pydantic v2. Hypothesis and
  jsonschema are development-only. Every non-project lock source must be the
  exact PyPI registry and every available artifact must carry a SHA-256 hash.
- [x] Every ordinary development, test, schema, build, and acceptance command
  enters through the fixed launcher and expands to an offline or no-sync uv
  form. The only non-offline
  commands are the two exact, one-time, separately approved Task 1 bootstrap
  commands; neither is verification evidence.
- [x] `scripts/verify.ps1` has exactly ten fail-fast operations in the reviewed
  order, checks schemas before tests and distribution after the offline build,
  restores the repository location in `finally`, and rejects extra raw
  package/network/shell command forms through a tested closure guard.
- [x] Application source has a closed import-root allowlist and alias-aware
  ambient-access scan. The fresh isolated child guards file reads/writes,
  environment/profile/registry access, network access, and process launch. Its
  sole Pydantic plugin-control response is fixed and reads no ambient value.
- [x] Canonical JSON, IDs, Decimal, UTC, diagnostics, explicit configuration,
  dataset metadata, descriptors, stable-version selection, and artifact owners
  have focused red/green tests plus property, schema, import, and source guards.
- [x] Configuration reads are explicit and bounded before decode/parse; path
  checks are lexical and ECMA-262-compatible in emitted schemas; every public
  configuration hash/snapshot entry revalidates a defensive copy.
- [x] Schema generation is explicit-output and import-pure, refuses unexpected
  files or symlink entries without deleting them, and does not overclaim physical
  containment through ancestor reparse points. Source, wheel, and sdist checks
  reject missing, duplicate, wrong-byte, wrong-root, backslash, link, special,
  and unexpected schema payloads.
- [x] Stage 2 remains `DISABLED_WITH_EVIDENCE`; GitNexus is never invoked and
  manual source/reference/base-to-HEAD review remains the advisory fallback.
- [x] No engine, exchange, network client, subprocess runtime, persistence,
  ingestion, orchestration, protocol envelope, finalization, live trading,
  credential, deployment, or Stage 4 feature enters Stage 3.
- [x] The plan contains no vague or unresolved instruction. The one future commit
  binding token is governed by an exact capture, validation, replacement, and
  absence check before staging, so it is not an unresolved decision.

Execution approval must be separate. Do not begin Stage 3 from this planning
worktree and do not mark the roadmap complete from planning evidence.

---
