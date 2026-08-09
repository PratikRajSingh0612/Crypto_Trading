# Project 1 — Engine-Neutral Core for a Local Seven-Engine Trading Research Lab

## 1. Title and document status

**Document:** Engine-Neutral Core Architecture Specification
**Project:** Project 1
**Status:** Approved architecture handoff; implementation has not started
**Date:** 2026-08-10
**Intended audience:** The implementation-plan author, implementers, reviewers, and the future maintainer of the local research lab

This document is the normative design for Project 1. It records an already approved product direction and architecture boundary. It authorizes documentation only; it does not install an engine, create implementation code, initiate an implementation plan, or enable any form of real-money trading.

The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** express architectural requirements. Examples and pseudocode clarify contracts but are not implementation.

## 2. Executive summary

Project 1 establishes the deterministic, engine-neutral foundation for a personal Windows application that will eventually compare research and simulated-trading behavior across seven isolated trading engines. The core is a Python 3.12 orchestrator with strict static typing, Pydantic v2 canonical records, versioned schemas, deterministic capability resolution, SQLite metadata registries, immutable file artifacts, and supervised adapter subprocesses.

The architecture deliberately separates the system of record from every trading engine. Engines never run inside the core process and never write to the core database. A future adapter for each engine will execute in its own compatible runtime and communicate through a versioned executable protocol composed of request files, JSON Lines events, result manifests, explicit exit categories, and immutable artifacts.

The approved strategy model is hybrid portability:

- Shared deterministic strategy specifications are portable where economic equivalence is meaningful.
- Explicit engine extensions are permitted only inside isolated adapter runtimes.
- A strategy is not forced through an engine that cannot model its requirements.
- Incompatibility is recorded as `NOT_APPLICABLE`, not as a failed experiment.
- Engine disagreement is evidence for diagnosis; results are never combined through majority voting or averaged into a synthetic return.

Project 1 defines contracts, records, state machines, persistence boundaries, artifact rules, and fake-adapter tests. It does not install or integrate the seven engines, download data, run backtests, implement a paper wallet, calculate Indian taxes, create a dashboard, or add an LLM.

## 3. Approved context

The product is a personal, local-only research and simulated-trading application running on Windows. Its initial trading domain is deliberately narrow:

- Binance Spot instruments quoted in USDT
- Long-only strategies
- No leverage and no futures
- Historical research and backtesting
- Always-available hypothetical-money trading in a later project
- Indian tax-adjusted analysis in a later project
- No real-money order placement
- No exchange credentials or API-key handling
- Local LLM analysis only after deterministic research and paper-trading behavior is reliable

The eventual research lab is planned to integrate:

1. VectorBT Community
2. Freqtrade
3. NautilusTrader
4. Jesse
5. OctoBot
6. Hummingbot
7. QuantConnect LEAN

Project 1 treats all framework-specific capability statements as planned adapter intent. Exact capabilities, operating-system behavior, supported versions, and limitations MUST be verified against a pinned framework version during that engine's adapter project.

The core vocabulary may represent broader markets, directions, data types, and `runtime.live` so future compatibility can be described without a schema break. Policy enforcement nevertheless prohibits live execution, short selling, margin, futures, leverage, credentials, and withdrawal behavior in the approved application scope.

## 4. Goals

Project 1 MUST:

1. Define canonical, validated, versioned engine-neutral domain records.
2. Define a declarative, deterministic, versioned portable strategy format for bar-based strategies.
3. Express strategy requirements and adapter capabilities through a versioned vocabulary.
4. Resolve compatibility deterministically as `SUPPORTED`, `SUPPORTED_WITH_APPROXIMATION`, `NOT_APPLICABLE`, or `UNAVAILABLE`.
5. Define an executable adapter protocol that keeps all engine code outside the orchestrator process.
6. Make the core authoritative for experiments, runs, datasets, artifacts, diagnostics, and audit records.
7. Make all material experiment inputs immutable once an experiment enters `QUEUED`.
8. Preserve engine-native outputs while also storing provenance-linked canonical results.
9. Make run identity, inputs, versions, warnings, and approximations reproducible and auditable.
10. Survive adapter crashes, malformed output, timeouts, cancellation, and application restart without false success or false finalization.
11. Provide strict path, schema, protocol, and process boundaries suitable for local use without claiming operating-system sandboxing.
12. Define enough module, interface, lifecycle, storage, and test detail for a separate implementation-plan task.
13. Keep all Project 1 tests independent of the seven real engines by using fake adapters.
14. Preserve extension points for future paper trading, Indian tax analysis, local LLM analysis, and Indian equities without coupling those concerns into the core domain.

## 5. Non-goals

Project 1 explicitly excludes all of the following:

- Installing any trading engine
- Implementing any trading-engine adapter
- Binance API integration
- Downloading or normalizing real market data
- Running a backtest
- Paper-wallet implementation
- India tax calculations
- Tax Deducted at Source calculations
- Risk-engine implementation
- Dashboard implementation
- Local LLM integration
- Live trading
- Exchange credentials
- API-key handling
- Withdrawal functionality
- Cloud deployment
- Docker
- Server deployment
- Strategy optimization
- Strategy promotion or approval decisions
- Verifying current engine-specific capabilities

Project 1 also does not create an operating-system security sandbox. Child-process isolation, explicit command invocation, bounded I/O, and path validation reduce accidental or faulty behavior; they do not make an untrusted engine executable safe.

## 6. System boundaries

### 6.1 Inside the Project 1 core

| Boundary | Project 1 responsibility |
|---|---|
| Canonical domain | Identifiers, financial values, timestamps, strategy, capability, experiment, run, artifact, result, diagnostic, and audit records |
| Strategy ingestion | Safe YAML parsing, canonical Pydantic validation, expression validation, and strategy hashing |
| Capability resolution | Versioned vocabulary, deterministic compatibility decisions, and approximation records |
| Adapter contracts | Descriptor, request, event, manifest, command, version-negotiation, and exit-code contracts |
| Registries | Experiment, run, dataset, artifact, strategy-version, diagnostic, and audit metadata |
| Artifact control | Validation, hashing, manifest creation, atomic finalization, immutability, and provenance |
| Process supervision | Argument-array launch, PID identity, protocol parsing, heartbeat, timeout, cancellation, termination, and restart reconciliation |
| Configuration | Safe local TOML configuration with deterministic precedence and immutable run snapshots |
| Persistence | SQLite/SQLAlchemy repositories, units of work, migrations, constraints, and recovery metadata |
| Observability | Structured local logs, protocol-event capture, diagnostics, and append-only audit facts |
| Verification | Unit, contract, integration, property-based, and Windows platform tests using fake adapters |

### 6.2 Outside the Project 1 core

The following remain external even in later projects:

- Engine-native execution algorithms and databases
- Engine-specific strategy lifecycle code
- Engine-specific package and runtime management
- Exchange connectivity
- Credential storage
- Market-data vendor or exchange clients
- User-interface rendering
- Tax policy logic
- LLM inference

The core may own contracts consumed by these components, but it MUST NOT absorb their implementation details.

### 6.3 Trust boundaries

1. **Human-authored input boundary:** TOML and strategy YAML are untrusted until parsed with safe parsers and validated against strict models.
2. **Adapter boundary:** Every adapter process and every byte it emits are untrusted until protocol and schema validation succeed.
3. **Filesystem boundary:** A path supplied by a request, event, or manifest is untrusted until resolved and proven to remain within its assigned root.
4. **Artifact boundary:** Engine-native output is untrusted until size, type, checksum, schema, and provenance validation complete.
5. **Persistence boundary:** Only core repository implementations may mutate core SQLite state. Engines and adapters receive no database handle or database path for writing.
6. **Future network boundary:** Project 1 performs no implicit network activity. Later adapters must explicitly declare any network requirement and remain subject to policy.

## 7. Architecture overview

```mermaid
flowchart LR
    User["Local user"] --> CLI["Core CLI and composition root"]
    CLI --> App["Experiment application service"]
    App --> Strategy["Strategy validator and versioner"]
    App --> Compat["Capability and compatibility resolver"]
    App --> Dataset["Dataset registry"]
    App --> Supervisor["Subprocess supervisor"]
    App --> Artifact["Artifact validator and finalizer"]
    App --> Audit["Audit and diagnostic services"]

    Strategy --> Domain["Canonical Pydantic domain models"]
    Compat --> Domain
    Dataset --> Domain
    Supervisor --> Protocol["Versioned adapter protocol"]
    Protocol --> Domain
    Artifact --> Domain
    Audit --> Domain

    App --> Ports["Repository and unit-of-work ports"]
    Ports --> Persistence["SQLAlchemy 2.x and SQLite WAL"]

    Supervisor -->|"argument array + request files"| Adapter["Isolated future adapter process"]
    Adapter -->|"JSON Lines events on stdout"| Supervisor
    Adapter -->|"human-readable logs on stderr"| Supervisor
    Adapter -->|"files in assigned temporary run directory"| Temp["Temporary run directory"]
    Temp --> Artifact
    Artifact --> Final["Immutable finalized artifact store"]

    Persistence --> Metadata["Authoritative metadata and state"]
    Audit --> Logs["Bounded local JSON Lines logs"]
```

### 7.1 Primary control flow

1. The local entry point loads deterministic non-secret configuration.
2. A strategy YAML document is safely parsed, strictly validated, normalized, and content-hashed.
3. An existing validated dataset version is selected by immutable hash; Project 1 uses fixtures only.
4. An `ExperimentSpec` captures every material input and selected engine intent.
5. Compatibility is resolved from strategy requirements, comparison level, adapter descriptor, and runtime availability.
6. The experiment becomes immutable when a transaction moves it to `QUEUED`.
7. Each eligible engine slot creates a distinct `EngineRunRecord` attempt and a request snapshot.
8. The supervisor launches the adapter executable using an argument array and an assigned temporary directory.
9. The core parses and validates JSON Lines events, captures bounded stderr, monitors heartbeats and deadlines, and persists significant state transitions.
10. The adapter writes large native and canonical candidate outputs within its assigned directory and writes its `AdapterResultManifest` semantic declaration.
11. The core validates that adapter manifest and its candidate artifacts, calculates its own checksums, preserves native output, atomically finalizes accepted files, and creates the authoritative core `RunManifest` and metadata.
12. The experiment aggregate derives its terminal state from child-run outcomes according to deterministic rules.

No adapter event, exit code, native report, or manifest is trusted by itself. Success requires a permitted lifecycle transition plus reconciliation of the matching `AdapterResultManifest`, process outcome, core `RunManifest`, and finalized artifacts.

### 7.2 Local dispatch model

Project 1 uses a local in-process scheduler owned by the `experiments` application package. A CLI command validates and queues an experiment transactionally, then drives eligible slots until the experiment reaches a terminal state or the user cancels. There is no background Windows service, daemon, server, remote worker, or persistent message broker.

The scheduler claims work through repository compare-and-swap leases so a restarted CLI cannot duplicate a run. `max_concurrent_runs` defaults to one and is bounded from one through eight by configuration; the observed value is audited. Concurrency changes scheduling and resource pressure but not economic assumptions. Each run remains isolated by request hash, attempt token, work directory, event sequence, and finalization lease.

Queue order is deterministic by experiment queue timestamp, engine-slot ordinal, and attempt number. Retry attempts for an active experiment enter the same ordered queue. Scheduling never changes adapter selection, compatibility, comparison level, or immutable inputs.

## 8. Dependency direction

```mermaid
flowchart TD
    CLI["cli: composition and local commands"] --> Experiments["experiments: application orchestration"]
    CLI --> Configuration["configuration: typed TOML loading"]
    CLI --> Persistence["persistence: concrete repositories"]

    Experiments --> Strategy["strategy: portable source and expressions"]
    Experiments --> Capabilities["capabilities: deterministic resolver"]
    Experiments --> Adapters["adapters: protocol contracts"]
    Experiments --> Datasets["datasets: registry service and ports"]
    Experiments --> Artifacts["artifacts: validation and finalization"]
    Experiments --> Process["process_supervision: child lifecycle"]
    Experiments --> Audit["audit: diagnostics and audit ports"]

    Strategy --> Domain["domain: canonical records and invariants"]
    Capabilities --> Domain
    Adapters --> Domain
    Datasets --> Domain
    Artifacts --> Domain
    Process --> Adapters
    Process --> Domain
    Audit --> Domain
    Configuration --> Domain

    Persistence --> Domain
    Persistence --> PortContracts["application-owned repository ports"]
    Experiments --> PortContracts

    Domain --> Nothing["No adapters, persistence, subprocess, or engine dependencies"]
```

Arrows mean “imports or depends on.” The dependency rules are:

- `domain` is pure and engine-neutral. It MUST NOT import adapters, persistence, process APIs, configuration readers, CLIs, or engine libraries.
- Canonical record types and state-transition invariants live in `domain`; behavior that coordinates I/O does not.
- `strategy`, `capabilities`, and `adapters` may depend on canonical domain types but not on concrete persistence or engine packages.
- `experiments` is the application layer. It coordinates ports and services but does not instantiate SQLite sessions or operating-system processes directly.
- Repository protocols are owned by the application package that consumes them. `persistence` implements those protocols; the application does not import concrete implementations.
- `process_supervision` implements an application-facing `ProcessSupervisor` port using adapter protocol types. It does not make economic trading decisions.
- `cli` is the composition root. It may depend on concrete implementations solely to wire them to abstract ports.
- Future engine adapter code resides outside the central package and central runtime.

### 8.1 Required core interfaces

The later implementation plan MUST provide narrowly scoped interfaces equivalent to these contracts:

| Interface | Owner | Responsibility |
|---|---|---|
| `StrategyLoader` | `strategy` | Convert safe YAML bytes into a validated `StrategySpec` and `StrategyVersion` |
| `CompatibilityResolver` | `capabilities` | Resolve one immutable requirement set against one adapter descriptor and runtime observation |
| `AdapterCatalog` | `adapters` | Return explicitly registered adapter executable descriptors; never scan arbitrary directories |
| `ExperimentRepository` | `experiments` | Persist and compare-and-swap experiment records and immutable specs |
| `EngineRunRepository` | `experiments` | Persist attempts, transitions, leases, heartbeats, exit facts, and terminal results |
| `DatasetRepository` | `datasets` | Resolve immutable dataset descriptors and partitions by ID and hash |
| `ArtifactRepository` | `artifacts` | Record staged/finalized artifacts, checksums, manifests, and provenance |
| `AuditSink` | `audit` | Append stable structured audit facts and correlated diagnostics |
| `UnitOfWork` | application boundary | Commit related registry mutations atomically or roll them back |
| `ProcessSupervisor` | `process_supervision` | Run one adapter command under deadlines, protocol limits, and cancellation |
| `ArtifactFinalizer` | `artifacts` | Validate, hash, manifest, atomically move, and register artifacts |
| `Clock` | `domain` port | Supply timezone-aware UTC instants and deterministic test clocks |
| `ContentHasher` | `domain` port | Produce canonical SHA-256 digests from normalized bytes |

Each interface MUST accept and return canonical types, explicit result objects, or stable diagnostics. It MUST NOT use an untyped dictionary as its public contract when a canonical model is available.

### 8.2 Interface operation contracts

The following signatures are normative at the operation level. Names may move between files during implementation planning, but parameters, ownership, sync/async behavior, and result semantics must remain equivalent. `Result[T]` is a discriminated success-or-diagnostics value; expected boundary failures are not communicated only through exceptions.

```text
StrategyLoader.load(source: bytes, source_name: str, observed_at_utc: datetime) -> Result[StrategyVersion]

CompatibilityResolver.resolve(
    requirements: tuple[CapabilityRequirement, ...],
    descriptor: AdapterDescriptor,
    availability: RuntimeAvailabilityObservation,
    comparison_level: ComparisonLevel,
    policy: CompatibilityPolicy,
) -> CompatibilityResult

AdapterCatalog.get(adapter_name: str, adapter_version: str) -> Result[AdapterCatalogEntry]
AdapterCatalog.list_registered() -> tuple[AdapterCatalogEntry, ...]

ExperimentRepository.get(experiment_id: ExperimentId) -> Result[ExperimentRecord]
ExperimentRepository.add(record: ExperimentRecord) -> Result[None]
ExperimentRepository.compare_and_swap(
    expected_revision: int,
    replacement: ExperimentRecord,
) -> Result[ExperimentRecord]

EngineRunRepository.get(run_id: RunId) -> Result[EngineRunRecord]
EngineRunRepository.add_attempt(record: EngineRunRecord) -> Result[None]
EngineRunRepository.compare_and_swap(
    expected_revision: int,
    replacement: EngineRunRecord,
) -> Result[EngineRunRecord]
EngineRunRepository.append_event(event: RunEvent) -> Result[RunEvent]

DatasetRepository.get_by_hash(content_hash: Sha256) -> Result[DatasetDescriptor]
DatasetRepository.list_partitions(dataset_id: DatasetId) -> Result[tuple[DatasetPartition, ...]]

ArtifactRepository.get(artifact_id: ArtifactId) -> Result[ArtifactRef]
ArtifactRepository.record_finalization(result: FinalizationResult) -> Result[tuple[ArtifactRef, ...]]

AuditSink.append(event: AuditEvent) -> Result[None]

UnitOfWork.begin() -> UnitOfWork
UnitOfWork.commit() -> Result[None]
UnitOfWork.rollback() -> None

async ProcessSupervisor.invoke(
    command: AdapterCommand,
    cancellation: CancellationToken,
) -> CommandResult

async ArtifactFinalizer.finalize(
    request: FinalizationRequest,
    cancellation: CancellationToken,
) -> FinalizationResult

ComparisonEligibilityService.evaluate(
    left: RunManifest,
    right: RunManifest,
    requested_level: ComparisonLevel,
) -> ComparisonEligibilityResult

Clock.now_utc() -> datetime
Clock.monotonic() -> MonotonicInstant
ContentHasher.sha256_stream(source: BinaryIO) -> Sha256
```

Repository and unit-of-work operations are synchronous because SQLite transactions are short local operations. Subprocess invocation and artifact hashing/finalization are asynchronous and cancellable because they can wait on external I/O. An application service owns the unit of work; repositories never commit independently. No database transaction remains open across adapter execution, heartbeat waiting, large-file hashing, or filesystem moves.

Infrastructure exceptions are caught at their owning boundary and converted to stable `Result` diagnostics. Programmer defects and violated internal invariants may raise internally, but the outer application boundary records `CORE.INVARIANT_VIOLATION` before returning a failed command result. Cancellation is an explicit token and result category, not an unstructured task exception.

## 9. Technology decisions

| Concern | Approved decision | Architectural consequence |
|---|---|---|
| Core language | Python 3.12 | The orchestrator has one pinned central runtime independent of engine runtimes |
| Typing | Strict static typing | Public interfaces, state transitions, event payloads, and repository boundaries are fully typed; unchecked dynamic data stops at validation boundaries |
| Dependency management | `uv` | The central lockfile and virtual environment are separate from every engine runtime |
| Canonical validation | Pydantic v2 | Unknown fields are rejected by default; versioned JSON Schemas are generated from canonical models |
| Metadata persistence | SQLite in WAL mode | Local transactional registries support concurrent readers and one controlled writer |
| Persistence boundary | SQLAlchemy 2.x | Repositories and units of work hide SQL and sessions from application services |
| Schema migration | Alembic | Database changes are explicit, ordered, reviewable, and never inferred from model drift |
| Large tabular data | Parquet | Candle partitions, normalized result series, fills, positions, and equity curves use typed columnar artifacts |
| Small structured data | JSON | Manifests, protocol request files, descriptor files, and small artifacts use canonical JSON |
| Event and log streams | JSON Lines | One bounded record per line supports incremental subprocess parsing and local structured logs |
| Human strategy source | YAML | Safe, declarative authoring is converted immediately to a canonical validated model |
| Application configuration | TOML | Local non-secret configuration has deterministic precedence and strict validation |
| Process isolation | Child process per adapter command | No engine is imported into the core; crashes and incompatible runtimes remain outside it |
| Large-value arithmetic | `Decimal` | Authoritative financial values never use binary floating point |
| Time | Timezone-aware UTC | Canonical timestamps serialize as RFC 3339 strings ending in `Z`; naive datetimes are rejected |
| Content identity | SHA-256 | Datasets, strategies, configuration snapshots, and finalized files have stable content identities |

The central project may select concrete linting, type-checking, and safe-YAML libraries during implementation planning, but those choices MUST enforce the contracts above and MUST NOT weaken strict typing, safe parsing, or rejection of arbitrary YAML tags.

## 10. Canonical identity and reproducibility

### 10.1 Operational identifiers

Operational records use UUID4 values rendered in lowercase canonical form and prefixed by record purpose:

- `exp_<uuid4>` for an experiment
- `run_<uuid4>` for an engine-run attempt
- `art_<uuid4>` for an artifact record

Additional internal identifiers use explicit prefixes such as `ds_` for dataset records, `strat_` for strategy definitions, `evt_` for run events, `diag_` for diagnostics, and `audit_` for audit events. Prefix validation prevents one identifier class from being accepted as another. UUIDs provide operational uniqueness; they do not replace content hashes.

### 10.2 Content hashes

SHA-256 is authoritative for:

- Validated canonical strategy versions
- Dataset versions and partition manifests
- Normalized material configuration snapshots
- Engine-extension modules declared by a strategy
- Finalized artifact files
- Canonical result manifests

Hash inputs MUST be deterministic bytes. Canonical JSON is UTF-8 without a byte-order mark, uses sorted object keys, compact separators, preserved array order, normalized version strings, Decimal strings, and UTC `Z` timestamps. Fields explicitly marked non-material, such as local display paths or ingestion wall-clock timestamps, are excluded only by a named versioned hashing profile. A hashing profile change creates a new schema/version contract; it never silently changes an existing digest.

YAML text itself is not the strategy identity. The strategy-version hash covers the canonical validated strategy model, the strategy hashing-profile version, and every explicitly declared extension-module hash. Comments, key ordering, and harmless YAML formatting therefore do not change strategy identity.

Dataset identity covers the normalized dataset manifest, ordered partition identities, raw and normalized checksums, normalization version, instrument identity, data type, interval, timeframe where applicable, and quality declarations. The implementation MUST stream large-file hashing and MUST NOT load large artifacts entirely into memory.

### 10.3 Required run provenance

Every `EngineRunRecord` and `RunManifest` MUST retain:

- Experiment ID and immutable experiment-spec hash
- Run ID, logical engine slot, attempt number, and attempt identity; raw attempt tokens exist only in adapter-bound requests, events, and `AdapterResultManifest` files, while core-owned records retain the token hash
- Strategy-version hash
- Dataset-version hash
- Engine name and pinned engine version
- Adapter name and pinned adapter version
- Canonical configuration hash
- Negotiated protocol version
- Negotiated schema versions
- Capability-vocabulary version
- Requested comparison level
- Start and completion timestamps
- All warnings and approximation declarations
- Native and normalized artifact references and checksums
- Process exit category and semantic result status

A run is reproducible only when all required provenance fields exist, referenced artifacts validate, and no material input is represented solely by a mutable path or ambient process state. Reproducibility means inputs and assumptions can be reconstructed; it does not promise numerically identical Level 3 outcomes across different operating systems, hardware, or nondeterministic engine internals. Such limitations MUST be recorded.

### 10.4 Versions and migrations

Every persisted or cross-process record has an explicit `schema_version`. Every adapter envelope has an explicit `protocol_version`. Readers reject unknown major versions and unknown fields by default. Backward compatibility is implemented through explicit, tested migrations that:

1. Read a known earlier immutable representation.
2. Produce a new representation without altering the original artifact.
3. Record the migration name, version, timestamp, input hash, output hash, and diagnostic warnings.
4. Preserve provenance back to the original record.

Silent reinterpretation of stored JSON, Parquet schemas, strategy files, or database columns is prohibited.

## 11. Canonical domain model

### 11.1 Common model rules

Canonical models are Pydantic v2 models configured to reject unknown fields. Cross-process and persisted top-level records include `schema_version`; operational records include stable identifiers and UTC creation timestamps. Values are validated before use and serialized only through versioned canonical serializers.

The following rules apply across the model:

- Financial values are `Decimal` in memory and canonical decimal strings in JSON. Exponents are normalized, negative zero is forbidden, non-finite values are forbidden, and scale constraints are explicit where an instrument supplies precision.
- Canonical timestamps are timezone-aware UTC instants serialized with RFC 3339 and a `Z` suffix. Naive datetimes and non-UTC offsets at canonical boundaries are rejected rather than silently converted.
- Enum values serialize as stable uppercase or namespaced strings documented by their schema.
- Asset, venue, engine, adapter, and capability names use normalized identifiers; separate display labels may retain user-facing spelling.
- Lists whose order has no economic meaning are sorted before canonical hashing. Lists whose order affects semantics, such as rule evaluation or event sequence, preserve order.
- Native engine symbols never replace canonical instrument identity.
- Every normalized record produced from engine output retains experiment, run, engine, adapter, source-artifact, and schema provenance.
- Models never accept arbitrary Python objects, callable values, class paths, pickles, or implicit code hooks.

### 11.2 Instrument identity

The canonical instrument form is:

```text
<VENUE>:<BASE>/<QUOTE>:<MARKET_TYPE>
```

For example:

```text
BINANCE:BTC/USDT:SPOT
```

`InstrumentRef` stores venue, base asset, quote asset, and market type as separate validated fields. An adapter-owned mapping may associate this identity with a native engine symbol, but that mapping is contextual to a pinned adapter and engine version. The canonical identity remains stable if two engines use different native symbols.

### 11.3 Required records

In the table below, “core-owned” means the accepted canonical copy and its lifecycle are authoritative in the core even when a human, dataset importer, or adapter produced the candidate data.

| Record | Purpose and ownership | Minimum fields | Validation and serialization |
|---|---|---|---|
| `InstrumentRef` | Core-owned normalized instrument identity | `schema_version`, `canonical_id`, `venue`, `base_asset`, `quote_asset`, `market_type` | Components are normalized and must reconstruct `canonical_id`; base and quote differ; market type is vocabulary-backed; native symbols are stored only in explicit mappings |
| `Money` | Currency-denominated amount | `schema_version`, `currency`, `amount` | Currency is a normalized asset code; amount is a finite `Decimal` string; sign constraints are imposed by the containing record |
| `Price` | Quote-currency value per base unit | `schema_version`, `instrument_id`, `quote_asset`, `value` | Instrument quote asset must match; value is a positive finite `Decimal` string and respects declared price precision when available |
| `Quantity` | Base-asset quantity for an instrument | `schema_version`, `instrument_id`, `base_asset`, `value` | Instrument base asset must match; value is a non-negative finite `Decimal` string and respects quantity precision when available |
| `Fee` | Canonical fee linked to an execution fact | `schema_version`, `fee_id`, `run_id`, `fill_id`, `amount`, `fee_type`, `timestamp_utc`, `source_artifact_id` | Fee amount currency is explicit; rebates use a named fee type rather than an ambiguous sign convention; provenance is mandatory |
| `DatasetDescriptor` | Authoritative metadata for one immutable dataset version | `schema_version`, `dataset_id`, `content_hash`, `source`, `venue`, `instrument`, `data_type`, `timeframe`, `start_utc`, `end_utc`, `normalization_version`, `validation_status`, `partition_ids`, `created_at_utc` | Time bounds are ordered and UTC; timeframe is required only where applicable; hash and partition order follow the dataset hashing profile |
| `DatasetPartition` | Immutable unit of large tabular data | `schema_version`, `partition_id`, `dataset_id`, `relative_path`, `content_hash`, `row_count`, `start_utc`, `end_utc`, `raw_checksum`, `normalized_checksum`, `column_schema_version` | Path must be registry-relative and confined to the dataset root; checksums use SHA-256; bounds and row count agree with validated metadata |
| `StrategySpec` | Canonical form of the portable strategy | All fields in section 12, including version, identity, rules, requirements, assumptions, and authoring metadata | Derived from safe YAML; unknown fields, unknown expression operators, arbitrary tags, and executable values are rejected |
| `StrategyVersion` | Immutable content identity for a validated strategy | `schema_version`, `strategy_version_id`, `strategy_id`, `content_hash`, `strategy_spec`, `extension_hashes`, `hashing_profile_version`, `created_at_utc` | Hash is recomputed from canonical content; extension declarations and hashes must match exactly; the accepted record is immutable |
| `CapabilityRequirement` | One strategy or comparison requirement | `schema_version`, `capability`, `required`, `minimum_semantics`, `approximation_policy`, `comparison_levels` | Capability must exist in the declared vocabulary version; approximation policy is explicit rather than inferred |
| `CapabilityDeclaration` | Adapter claim for one vocabulary item | `schema_version`, `capability`, `support_kind`, `evidence_note`, `limitations` | `support_kind` is `NATIVE`, `APPROXIMATED`, or `UNSUPPORTED`; approximated declarations reference an `ApproximationDeclaration` |
| `ApproximationDeclaration` | Machine-readable account of non-native behavior | `schema_version`, `approximation_id`, `capability`, `method`, `expected_impact`, `prevented_comparison_levels`, `adapter_version` | Required text fields are non-empty and bounded; prevented levels are an ordered unique set; declaration version is included in run provenance |
| `EngineDescriptor` | Core-owned description of a pinned engine version | `schema_version`, `engine_name`, `engine_version`, `engine_family`, `planned_role`, `known_limitations` | Names and versions are explicit; no unversioned “latest” value is accepted; capabilities are not inferred from the engine name |
| `AdapterDescriptor` | Validated output of `describe` and catalog registration | `schema_version`, `adapter_name`, `adapter_version`, `engine`, `supported_protocol_versions`, `supported_schema_versions`, `capability_vocabulary_version`, `native_capabilities`, `approximated_capabilities`, `unsupported_capabilities`, `supported_operating_systems`, `runtime_requirements`, `network_required`, `credentials_required`, `known_modeling_limitations`, `executable_hash` | Capability sets are disjoint and complete for claims made; versions are non-empty and ordered deterministically; the descriptor may report network or credential requirements, while Project 1 policy prohibits executing any operation that requires them |
| `RuntimeAvailabilityObservation` | Time-bounded local observation used separately from logical capabilities | `schema_version`, `adapter_name`, `adapter_version`, `executable_path`, `executable_hash`, `runtime_version`, `operating_system`, `available`, `reason_code`, `observed_at_utc`, `expires_at_utc`, `network_required`, `credentials_required` | Expiry follows observation time; availability cannot override semantic incompatibility or safety policy; paths and hashes come from the explicit catalog |
| `NegotiationResult` | Deterministic protocol/schema/vocabulary selection | `schema_version`, `adapter_name`, `candidate_protocol_versions`, `candidate_schema_versions`, `candidate_vocabulary_versions`, `selected_protocol_version`, `selected_schema_versions`, `selected_vocabulary_version`, `outcome`, `diagnostics` | Candidate lists are sorted and complete; selected values belong to intersections; failed negotiation has no selected values and makes the adapter unavailable |
| `AdapterValidationResult` | Adapter-produced result of the `validate` command | `schema_version`, `protocol_version`, `request_id`, `run_id`, `attempt_token`, `outcome`, `diagnostics`, `validated_at_utc`, `result_hash` | Outcome is `VALID`, `NOT_APPLICABLE`, `UNAVAILABLE`, or `INVALID`; identity and hash must match; no engine execution result or finalized artifact is represented |
| `CommandInvocationRecord` | Core-owned process facts for one `describe`, `validate`, or `run` subprocess | `schema_version`, `invocation_id`, `command_kind`, `adapter_name`, `adapter_version`, `run_id`, `request_hash`, `state`, `pid_identity`, `started_at_utc`, `completed_at_utc`, `process_exit_category`, `stderr_artifact_id`, `diagnostic_ids` | `run_id` is required for validate/run and absent for catalog-only describe; state governs process-field optionality; one invocation never spans commands |
| `ExperimentSpec` | Immutable material inputs for one comparison intent | `schema_version`, `strategy_version_hash`, `dataset_version_hash`, `selected_engine_slots`, `starting_balance`, `fee_assumptions`, `slippage_assumptions`, `execution_assumptions`, `comparison_level`, `configuration_hash`, `created_at_utc` | All money and rates use Decimal strings; engine-slot order is canonicalized; references resolve before queueing; any material change produces a new experiment |
| `ExperimentRecord` | Authoritative experiment lifecycle and immutable spec linkage | `schema_version`, `experiment_id`, `spec`, `spec_hash`, `state`, `created_at_utc`, `updated_at_utc`, `revision` | State changes use compare-and-swap on `revision`; `spec` cannot change at or after `QUEUED`; terminal records cannot transition |
| `EngineRunRequest` | Immutable adapter command payload for one attempt | `schema_version`, `protocol_version`, `request_id`, `experiment_id`, `run_id`, `logical_slot_id`, `attempt_number`, `attempt_token`, `strategy_version_hash`, `dataset_version_hash`, `adapter`, `engine`, `configuration_snapshot`, `configuration_hash`, `comparison_level`, `deadline_utc`, `assigned_work_dir`, `created_at_utc` | References and hashes must agree with the experiment; work directory is absolute in the launcher but serialized as an authorized root plus safe relative references; token is unique per attempt |
| `EngineRunRecord` | Authoritative state and process facts for one attempt | `schema_version`, `run_id`, `experiment_id`, `logical_slot_id`, `attempt_number`, `attempt_token_hash`, `state`, `adapter`, `engine`, `request_hash`, `created_at_utc`, `updated_at_utc`, `revision` | Attempt number is monotonic within a slot; transitions are compare-and-swap; process facts, heartbeat, exit, adapter/core manifest references, diagnostics, and predecessor run are explicit state-governed fields |
| `RunEvent` | Validated persisted event from an adapter or supervisor | `schema_version`, `protocol_version`, `event_id`, `run_id`, `attempt_token`, `sequence`, `event_type`, `timestamp_utc`, `payload`, `received_at_utc` | `(run_id, sequence)` is unique; sequence increases by one; event type selects a strict payload schema; size is bounded before parsing |
| `ArtifactRef` | Authoritative identity and provenance for one file artifact | `schema_version`, `artifact_id`, `artifact_kind`, `state`, `relative_path`, `content_hash`, `size_bytes`, `media_type`, `experiment_id`, `run_id`, `source_role`, `created_at_utc`, `finalized_at_utc` | Finalized path is core-controlled; checksum and size are independently recomputed; final records are immutable; source role distinguishes native, normalized, manifest, log, and diagnostic output |
| `AdapterResultManifest` | Adapter-produced final semantic declaration and candidate-artifact index | `schema_version`, `protocol_version`, `adapter_manifest_id`, `experiment_id`, `run_id`, `attempt_token`, `semantic_status`, `started_at_utc`, `completed_at_utc`, `provenance`, `candidate_artifacts`, `candidate_metrics`, `diagnostics`, `warnings`, `approximations`, `adapter_result_manifest_hash` | Written before process exit, so it contains no observed exit category or core artifact IDs; candidate paths are relative to the assigned directory; the core validates every claim |
| `RunManifest` | Core-generated authoritative consolidated record after successful process reconciliation and artifact finalization | `schema_version`, `protocol_version`, `manifest_id`, `experiment_id`, `run_id`, `attempt_token_hash`, `adapter_result_manifest_hash`, `semantic_status`, `process_exit_category`, `started_at_utc`, `completed_at_utc`, `provenance`, `artifact_refs`, `metrics`, `diagnostics`, `warnings`, `approximations`, `run_manifest_hash` | Built only by the core for `SUCCEEDED` or `SUCCEEDED_WITH_WARNINGS`; matching adapter semantic status, process outcome, lifecycle lease, and finalized `ArtifactRef`s must reconcile; an unknown lost exit is explicit and forces a recovery warning |
| `CanonicalOrder` | Normalized order intent or accepted engine order fact | `schema_version`, `order_id`, `experiment_id`, `run_id`, `source_artifact_id`, `instrument`, `side`, `position_effect`, `order_type`, `quantity`, `limit_price`, `time_in_force`, `submitted_at_utc`, `engine_order_id` | `BUY` opens or increases and `SELL` reduces or closes in long-only scope; negative quantities are forbidden; optional native ID never becomes canonical identity |
| `CanonicalFill` | Normalized execution fact | `schema_version`, `fill_id`, `order_id`, `experiment_id`, `run_id`, `source_artifact_id`, `instrument`, `side`, `quantity`, `price`, `fees`, `filled_at_utc`, `engine_fill_id` | Quantity and price are positive; fee currencies are explicit; fill cannot exceed modeled order constraints without a diagnostic |
| `PositionSnapshot` | Position state at a canonical instant | `schema_version`, `snapshot_id`, `experiment_id`, `run_id`, `source_artifact_id`, `instrument`, `quantity`, `average_entry_price`, `market_price`, `realized_pnl`, `unrealized_pnl`, `timestamp_utc` | Long-only quantity is non-negative; financial values are Decimal-based and currencies are explicit; snapshots are time ordered within a series |
| `PortfolioSnapshot` | Portfolio-level balance and valuation | `schema_version`, `snapshot_id`, `experiment_id`, `run_id`, `source_artifact_id`, `cash_balances`, `position_snapshot_ids`, `equity`, `timestamp_utc` | Asset balances and equity reconcile within declared precision or emit a diagnostic; no floating-point total is authoritative |
| `EquityPoint` | Compact normalized equity-series point | `schema_version`, `experiment_id`, `run_id`, `source_artifact_id`, `timestamp_utc`, `equity`, `cash`, `exposure` | Series is sorted by unique UTC timestamp; all amounts and ratios use Decimal strings |
| `MetricValue` | Named normalized result metric | `schema_version`, `metric_name`, `value`, `value_type`, `unit`, `methodology_version`, `comparison_level`, `source_artifact_id` | Numeric values are Decimal strings; units and methodology are mandatory; missing or undefined values use an explicit status rather than NaN |
| `Diagnostic` | Stable machine-readable warning or error | `schema_version`, `diagnostic_id`, `severity`, `error_code`, `category`, `message`, `source_component`, `experiment_id`, `run_id`, `engine`, `retriable`, `timestamp_utc`, `details`, `causal_diagnostic_ids` | Message and structured details are bounded and redacted; causal IDs cannot cycle; free-form exception text is supplementary only |
| `AuditEvent` | Append-only record of a meaningful core action | `schema_version`, `audit_event_id`, `action`, `actor`, `outcome`, `experiment_id`, `run_id`, `artifact_id`, `timestamp_utc`, `correlation_id`, `details_hash`, `details` | Actor is `LOCAL_USER`, `CORE`, or a named adapter identity; events are immutable, ordered, bounded, and contain no secrets |

### 11.4 Canonical versus native data

Canonical models define comparison contracts, not a claim that all engines natively share the same semantics. Native reports remain immutable artifacts. A converter may produce canonical records only when it can document the mapping, precision, timing semantics, and any approximation. A conversion failure does not delete or invalidate a valid native report; it produces a diagnostic and prevents the affected canonical comparison.

### 11.5 Field optionality and discriminators

Canonical boundary fields are required unless this specification makes their absence state-dependent. Models do not use implicit `None` defaults to hide missing data. Exact state-governed optionality is:

- `DatasetDescriptor.timeframe` is absent only for data types without a timeframe; OHLCV requires it.
- `EngineRunRecord` process identity exists only from `STARTING` onward; heartbeat exists only after one is observed; completion, exit, manifest, and terminal diagnostic fields exist only when their governing facts occur.
- `CommandInvocationRecord.run_id` is absent only for catalog-level `describe`; PID, completion, exit, and stderr reference fields follow invocation state.
- `ArtifactRef.finalized_at_utc` and finalized path exist only in `FINALIZED`; candidate paths never occupy the finalized-path field.
- `CanonicalOrder.limit_price` is required for limit orders and prohibited for market orders. Native order IDs remain optional provenance.
- `PositionSnapshot.average_entry_price` is absent only for a zero position; realized and unrealized PnL remain explicit Money values.
- A failed negotiation has no selected version; a successful negotiation requires every selected version.
- A core `RunManifest.process_exit_category` is either a known category or the explicit enum `UNKNOWN_AFTER_RESTART`, never an omitted field.
- A core `RunManifest` exists only for a run whose terminal state is `SUCCEEDED` or `SUCCEEDED_WITH_WARNINGS`; every other terminal outcome is represented by the `EngineRunRecord`, diagnostics, audit events, and any quarantined evidence rather than a core run manifest.

Discriminated unions use explicit fields such as `event_type`, `artifact_kind`, `command_kind`, `order_type`, `value_type`, and `semantic_status`. The initial normative enums are:

- `CompatibilityOutcome`: `SUPPORTED`, `SUPPORTED_WITH_APPROXIMATION`, `NOT_APPLICABLE`, `UNAVAILABLE`
- `ValidationOutcome`: `VALID`, `NOT_APPLICABLE`, `UNAVAILABLE`, `INVALID`
- `CommandKind`: `DESCRIBE`, `VALIDATE`, `RUN`
- `ArtifactState`: `CANDIDATE`, `VALIDATING`, `FINALIZING`, `FINALIZED`, `QUARANTINED`, `CORRUPT`
- `SemanticStatus`: `SUCCEEDED`, `SUCCEEDED_WITH_WARNINGS`, `FAILED`, `CANCELLED`, `TIMED_OUT`, `NOT_APPLICABLE`, `UNAVAILABLE`
- `OrderType`: `MARKET`, `LIMIT`
- `OrderSide`: `BUY`, `SELL`
- `PositionEffect`: `OPEN_OR_INCREASE`, `REDUCE_OR_CLOSE`
- `DiagnosticSeverity`: `INFO`, `WARNING`, `ERROR`, `CRITICAL`

Arrays default to no value only when absence has distinct semantics; otherwise schemas require an explicit empty array. Numeric bounds, string lengths, path lengths, and collection limits are declared in generated schemas and share compiled ceilings with process and artifact readers. `details` payloads use a bounded JSON-value union, never arbitrary Python types. These rules and the generated JSON Schemas are normative together; implementation planning may choose class layout but may not invent different field semantics.

## 12. Portable strategy specification

### 12.1 Source and canonical form

The human-authored portable strategy source is versioned YAML. It is parsed using a safe mode that rejects custom tags and object construction, then validated into a strict `StrategySpec` Pydantic model. The validated model, not raw YAML formatting, is authoritative for execution requests and hashing.

Version 1 targets deterministic bar-based strategies. It is intentionally not a general-purpose programming language and MUST NOT execute arbitrary Python, import modules, perform file I/O, access the network, read environment variables, or call engine APIs in the orchestrator.

### 12.2 Required fields

Version 1 contains:

- `schema_version`
- `strategy_id`
- `display_name`
- `description`
- `strategy_family`
- `market_type`
- `direction`
- `timeframe`
- `universe`
- `required_capabilities`
- `parameters`
- `features`
- `entry_rules`
- `exit_rules`
- `sizing_intent`
- `risk_assumptions`
- `warm_up_requirements`
- `comparison_requirements`
- `supported_approximation_policy`
- `engine_extensions`
- `authoring_metadata`

The initial policy accepts only `market_type: spot`, `direction: long`, and comparison runtimes allowed by the approved scope. The broader canonical vocabularies remain available for descriptor compatibility and future migrations.

### 12.3 Declarative expression model

Features form a directed acyclic graph. Each feature has a stable ID, a versioned operation from an allowlist, typed inputs, typed parameters, output type, warm-up length, and missing-value policy. Initial operation families cover source bar fields, arithmetic, comparisons, rolling aggregates, deterministic indicators, shifts, crossovers, and boolean composition.

Rules are validated expression trees referencing declared parameters and feature IDs. The grammar supports typed literals, `and`, `or`, `not`, relational comparisons, equality, `crosses_above`, `crosses_below`, and explicit bar offsets. It prohibits `eval`, arbitrary function names, reflection, imports, recursion, loops, mutation, wall-clock access, and nondeterministic random values.

Evaluation order follows graph dependencies and declared rule order. The same canonical input bars, warm-up policy, Decimal quantization rules, and expression-semantics version MUST yield the same Level 1 signal intent.

### 12.3.1 Expression AST and types

Every expression node is a discriminated object with an `op` field. The version 1 abstract syntax tree contains only:

- `literal`: typed `BOOLEAN`, `INTEGER`, `DECIMAL`, `STRING`, or canonical identifier value
- `ref`: a declared parameter, source field, or feature ID plus non-negative `bars_ago`
- Unary `not`, `negate`, and `is_missing`
- Arithmetic `add`, `subtract`, `multiply`, `divide`, `minimum`, and `maximum`
- Comparison `equal`, `not_equal`, `less_than`, `less_than_or_equal`, `greater_than`, and `greater_than_or_equal`
- Boolean `and` and `or` over ordered non-empty operand lists
- Temporal `crosses_above` and `crosses_below` over two numeric series

Operator signatures are fixed by `expression_semantics_version: expressions/v1`. Arithmetic accepts compatible numeric values and returns `DECIMAL`, except integer-only parameter validation remains integer. Comparison accepts compatible operands and returns `BOOLEAN`. Boolean operators accept booleans only. There is no implicit string-to-number, float-to-Decimal, asset-to-string, scalar-to-series, or timezone conversion.

A reference with `bars_ago: 0` reads the current fully closed bar; `bars_ago: 1` reads the prior closed bar. Negative offsets and access to a future or still-open bar are invalid. At bar `t`, `crosses_above(left, right)` is true exactly when both series are present at `t` and `t-1`, `left[t] > right[t]`, and `left[t-1] <= right[t-1]`. `crosses_below` uses the inverse inequalities.

Feature operations are separately versioned allowlist entries with typed signatures, including `source.bar_field/v1`, arithmetic/boolean expression projection, deterministic rolling aggregates, shift, and named deterministic indicators such as `indicator.sma/v1`. A feature graph must be acyclic, every input must exist and type-check, and declared warm-up must be at least the maximum dependency warm-up.

### 12.3.2 Missing values, warm-up, and quantization

Before a feature's declared warm-up completes, its value is `MISSING`. A top-level entry or exit rule containing `MISSING` evaluates to false; it never becomes true through truthiness. After warm-up, the strategy's explicit missing-data policy is one of `REJECT_DATASET`, `SKIP_BAR`, or `PROPAGATE_FALSE`. The chosen policy is material input and applies consistently across reference and adapter evaluations.

Canonical expression arithmetic uses a Decimal context with 34 significant digits and `ROUND_HALF_EVEN`. Division by zero, overflow beyond schema bounds, and invalid operations produce deterministic diagnostics. Indicator values are not quantized to instrument tick size. Prices and quantities are quantized only when sizing intent becomes an order intent, using the experiment's explicit instrument precision and rounding policy.

### 12.3.3 Reference semantics

Project 1 implements a pure reference expression evaluator for fixture-sized Level 1 contract examples. It validates feature/rule semantics and produces expected feature and signal series; it does not model orders, fills, portfolio accounting, optimization, or a backtest. Future adapters must pass golden Level 1 fixtures against this evaluator before claiming portable signal parity.

Golden examples cover first-valid warm-up bar, crossover equality boundaries, missing inputs, explicit bar offsets, Decimal rounding, entry and exit on adjacent bars, and invalid future references. The evaluator has no wall-clock, filesystem, network, engine, or random-number access.

### 12.4 Illustrative source shape

```yaml
schema_version: strategy/v1
strategy_id: sma_cross_long
display_name: SMA Cross Long
description: Enters long when a fast average crosses above a slow average and exits on the reverse cross.
strategy_family: trend_following
market_type: spot
direction: long
timeframe: 1h
universe:
  kind: static
  instruments:
    - BINANCE:BTC/USDT:SPOT
required_capabilities:
  - capability: market.spot
    required: true
  - capability: direction.long
    required: true
  - capability: data.ohlcv
    required: true
  - capability: execution.bar_market
    required: true
  - capability: runtime.backtest
    required: true
parameters:
  fast_period:
    type: integer
    value: 20
    minimum: 2
  slow_period:
    type: integer
    value: 50
    minimum: 3
features:
  - id: fast_sma
    operation: indicator.sma/v1
    inputs: [bar.close]
    parameters: {period: fast_period}
  - id: slow_sma
    operation: indicator.sma/v1
    inputs: [bar.close]
    parameters: {period: slow_period}
entry_rules:
  - id: enter_cross
    expression:
      op: crosses_above
      left: {op: ref, id: fast_sma, bars_ago: 0}
      right: {op: ref, id: slow_sma, bars_ago: 0}
exit_rules:
  - id: exit_cross
    expression:
      op: crosses_below
      left: {op: ref, id: fast_sma, bars_ago: 0}
      right: {op: ref, id: slow_sma, bars_ago: 0}
sizing_intent:
  method: fraction_of_available_quote
  fraction: "1"
risk_assumptions:
  leverage: "1"
  shorting_allowed: false
warm_up_requirements:
  minimum_bars: 50
comparison_requirements:
  maximum_level: 2
supported_approximation_policy:
  default: reject
engine_extensions: []
authoring_metadata:
  author: local_user
  created_at_utc: "2026-08-10T00:00:00Z"
```

This example communicates shape only. The generated JSON Schema is the normative field and union definition.

### 12.5 Parameters, universe, and economic meaning

- Parameters are typed values with optional bounds and units. A run request contains resolved immutable values, never an unresolved parameter sweep.
- A static universe lists canonical instrument IDs. A future registry-query universe must be resolved to an ordered immutable instrument list before the experiment is queued, and that resolved list becomes material input.
- Sizing describes economic intent, such as a fraction of available quote balance. An adapter declares whether it can implement the intent natively or through a documented approximation.
- Fee, slippage, timing, rounding, and starting-balance assumptions belong to the immutable experiment, while the strategy records only strategy-level requirements and acceptable approximation policy.
- Risk assumptions describe the strategy's expected boundaries but do not implement a risk engine.

### 12.6 Engine extensions

Future engine extensions are explicitly declared by adapter name, extension identifier, version, content hash, purpose, lifecycle effect, and economic-effect classification. They:

- Execute only inside the named adapter runtime.
- Are loaded only from explicit catalog entries, never discovered by scanning arbitrary directories.
- Contribute their hashes to the strategy-version hash.
- Declare whether they only adapt lifecycle hooks or alter execution behavior.
- MUST NOT silently change shared entry, exit, sizing, or risk meaning.
- Make a Level 1 or Level 2 comparison ineligible when their declared economic effect prevents parity.

The central core stores the declarations and hashes but never imports or executes extension code.

## 13. Capability and compatibility model

### 13.1 Versioned vocabulary

The initial vocabulary version is `capabilities/v1` and includes at least:

| Category | Capability names |
|---|---|
| Market | `market.spot`, `market.margin`, `market.futures`, `market.equities` |
| Direction | `direction.long`, `direction.short` |
| Data | `data.ohlcv`, `data.trades`, `data.quotes`, `data.order_book_l2` |
| Execution | `execution.bar_market`, `execution.bar_limit`, `execution.event_driven`, `execution.maker_orders`, `execution.partial_fills`, `execution.multiple_open_orders` |
| Portfolio | `portfolio.single_asset`, `portfolio.multi_asset`, `portfolio.multi_venue` |
| Research | `research.parameter_sweep`, `research.optimization`, `research.monte_carlo`, `research.walk_forward` |
| Runtime | `runtime.backtest`, `runtime.paper`, `runtime.live` |

`runtime.live` is descriptive vocabulary only. Project 1 policy rejects any request containing it before adapter selection or process launch. Its presence in a descriptor does not enable it.

Vocabulary evolution is additive within a compatible minor version. Renaming, removing, or changing the meaning of a capability requires a new major vocabulary version and explicit descriptor and strategy migrations.

### 13.2 Adapter declaration

For every capability an adapter claims, its descriptor places the capability in exactly one set:

- **Native:** The pinned engine/adapter implements the declared semantics without the adapter substituting a materially different model.
- **Approximated:** The adapter can produce a result only through a named approximation declaration.
- **Unsupported:** The adapter does not provide the required model.

Absence is not interpreted as native support. Unknown capability names or overlapping declarations invalidate the descriptor.

### 13.3 Deterministic resolution algorithm

Core safety-policy validation runs before compatibility resolution. A prohibited request, including live runtime, credentials, shorting, margin, futures, or leverage, produces a user/configuration diagnostic; no `CompatibilityResult` or engine-run attempt is created.

For policy-valid input, compatibility resolution is a pure function of the capability-policy version, strategy requirements, experiment assumptions, comparison level, adapter descriptor, and a separate runtime-availability observation. It returns exactly one of the four approved outcomes using this order:

1. Verify vocabulary, protocol, and schema versions are recognized and internally consistent.
2. Compare every required capability with the adapter's native, approximated, and unsupported sets.
3. If any required capability is unsupported or absent, return `NOT_APPLICABLE` with the complete list of unmet requirements.
4. If approximations are required, verify the strategy permits each approximation and that none prevents the requested comparison level. A disallowed approximation returns `NOT_APPLICABLE`.
5. If semantic compatibility is established but the adapter executable, engine runtime, pinned version, negotiated protocol, or required local configuration is not runnable, return `UNAVAILABLE`.
6. If every required capability is native and the runtime is available, return `SUPPORTED`.
7. If at least one allowed approximation is required and the runtime is available, return `SUPPORTED_WITH_APPROXIMATION` with all approximation records.

The resolver returns all reasons in stable capability-name order. It never stops at the first missing capability, guesses from an engine name, or treats runtime absence as strategy incompatibility.

### 13.4 Outcome semantics

| Outcome | Meaning | Run behavior |
|---|---|---|
| `SUPPORTED` | All required semantics are native and the runtime is available | A run attempt may proceed |
| `SUPPORTED_WITH_APPROXIMATION` | The runtime is available and every required approximation is explicitly allowed | A run may proceed with approximation records attached to request, events, manifest, and comparison eligibility |
| `NOT_APPLICABLE` | The engine cannot model at least one required strategy, data, execution, portfolio, or comparison semantic | Normally record before `run`; descriptor or adapter-specific `validate` may have executed. A late adapter discovery during `run` requires exit `20`, a matching adapter manifest, and a diagnostic |
| `UNAVAILABLE` | The adapter is logically compatible but is absent, misconfigured, version-incompatible, or not runnable | Record a terminal availability outcome; do not mislabel it as strategy failure |

Each `ApproximationDeclaration` identifies the capability, approximation method, expected impact, evidence note, and whether it prevents Level 1, Level 2, or Level 3 comparison. A result excluded from a level cannot enter that level's comparison set.

Compatibility results are never votes. A set of three `SUPPORTED` runs and two `NOT_APPLICABLE` results says nothing about strategy quality. Likewise, disagreement among successful runs remains a diagnostic subject, not an averaging instruction.

## 14. Adapter protocol

### 14.1 Executable operations

Each explicitly registered adapter exposes these logical commands:

```text
adapter-executable describe --output <descriptor-path>

adapter-executable validate
  --request <request-path>
  --output <validation-result-path>

adapter-executable run
  --request <request-path>
  --work-dir <assigned-temporary-directory>
  --result <final-manifest-path>
```

The orchestrator passes an argument array to the operating-system process API. Concatenated shell commands, `shell=True`, implicit shell expansion, and executable discovery from untrusted paths are prohibited. Executable paths come only from the explicit adapter catalog and are recorded with a checksum.

`describe` produces an `AdapterDescriptor`. `validate` performs adapter-specific validation without starting a backtest. `run` executes one immutable request and may write only inside its assigned directory. All commands use the same version-negotiation, exit-category, diagnostics, and bounded-output rules.

Every adapter subprocess invocation has a core-owned `CommandInvocationRecord` with `invocation_id`, command kind, adapter identity, optional run ID, request hash, start/end timestamps, PID identity where launched, process exit category, bounded stderr artifact, and diagnostics. `describe` and `validate` invocations may occur while an engine-run record is in `VALIDATING`; the run lifecycle describes the economic run attempt, while invocation records describe each child process used to reach that state.

`validate` writes a strict `AdapterValidationResult` containing protocol/schema versions, request/run/attempt identity, validation outcome, diagnostics, and adapter-specific applicability facts. Its outcome is `VALID`, `NOT_APPLICABLE`, `UNAVAILABLE`, or `INVALID`. A valid result permits the later `run` command; the other outcomes map to the corresponding engine-run terminal state or validation failure without launching `run`.

`run --result` points to an `AdapterResultManifest` inside the assigned temporary directory. That adapter-produced manifest is final for the adapter's semantic declaration but is still untrusted input to the core. After process reconciliation and artifact finalization, the core creates the authoritative consolidated `RunManifest`.

All request, descriptor-output, validation-output, work, and result paths are absolute core-selected paths under a command-specific temporary root. `describe` may write only its descriptor output; `validate` may write only its validation output and declared bounded diagnostics; `run` may write only within its assigned work directory. A `CommandResult` returned by the supervisor contains the finalized `CommandInvocationRecord`, observed exit category and native exit value, parsed output model when valid, bounded diagnostics, cancellation/timeout facts, and protocol-integrity status. The parsed output union is selected by `command_kind`: `AdapterDescriptor`, `AdapterValidationResult`, or `AdapterResultManifest`.

### 14.2 Version negotiation

The core validates `describe` output using the bootstrap descriptor schema supported by Project 1. It computes the intersection of core-supported and adapter-supported protocol and schema versions, then deterministically selects the highest mutually supported stable version according to semantic version ordering. The chosen versions are pinned in the request and run record.

An empty intersection makes a logically compatible adapter `UNAVAILABLE` with a version-negotiation diagnostic. The core never guesses a version or silently downgrades a stored request during execution.

The bootstrap descriptor envelope has fixed fields: `bootstrap_schema_version`, adapter name/version, engine name/version, executable hash, supported protocol versions, supported canonical schema versions, capability-vocabulary versions, and descriptor payload hash. A `NegotiationResult` records the sorted candidate intersections, selected versions, policy version, outcome, and diagnostics. A `RuntimeAvailabilityObservation` records executable presence/hash, runtime version observation, operating system, observed-at UTC, expiration UTC, network/credential requirement flags, and a stable availability reason. Availability is an observation with bounded lifetime, not a permanent capability declaration.

### 14.3 Request envelope

A request envelope contains:

- `protocol_version`
- `schema_version`
- `request_id`
- `command`
- `created_at_utc`
- `experiment_id`
- `run_id`
- `logical_slot_id`
- `attempt_number`
- `attempt_token`
- `payload_hash`
- `payload`

The payload for `validate` and `run` is an `EngineRunRequest` or a versioned projection of it. The adapter verifies the envelope, payload hash, versions, assigned path, and attempt identity before engine initialization.

### 14.4 Event envelope and event types

Every stdout line during `validate` or `run` MUST be non-empty and contain one complete UTF-8 JSON object with:

- `protocol_version`
- `schema_version`
- `event_id`
- `run_id`
- `attempt_token`
- `sequence`
- `event_type`
- `timestamp_utc`
- `payload`

Supported event types are:

| Event | Required payload semantics |
|---|---|
| `heartbeat` | Adapter monotonic activity counter, current phase, and optional bounded resource observation; no progress claim is implied |
| `progress` | Phase name, completed units, total units when known, and a Decimal percentage when meaningful |
| `warning` | Stable warning code, bounded message, structured impact, and comparison-level effect |
| `diagnostic` | Stable diagnostic structure with category, severity, retriable flag, and causal references |
| `artifact_produced` | Candidate relative path, artifact kind, media type, declared size, and adapter-computed checksum; the core independently validates all values |
| `final_result` | Relative `AdapterResultManifest` path, `adapter_result_manifest_hash` claimed by the adapter, and semantic-status summary; it is only a pointer and not authoritative without manifest validation |

Sequence numbers start at one and increase by exactly one. Duplicate, missing, out-of-order, wrong-run, or wrong-attempt events are protocol violations. Event receipt timestamps are recorded separately from adapter timestamps.

### 14.5 Subprocess interaction

```mermaid
sequenceDiagram
    participant Core as Core orchestrator
    participant Registry as Core registries
    participant Child as Isolated adapter process
    participant Work as Assigned temporary directory
    participant Store as Final artifact store

    Core->>Registry: Create run attempt and immutable request hash
    Core->>Work: Create unique assigned directory
    Core->>Child: Launch argument array with request and paths
    Child->>Core: JSON Lines heartbeat and progress events
    Core->>Registry: Validate and persist significant events
    Child->>Work: Write native and normalized candidate files
    Child->>Core: artifact_produced events
    Child->>Work: Write adapter result manifest candidate
    Child->>Core: final_result event
    Child-->>Core: Exit with process category
    Core->>Work: Validate manifest, paths, schemas, sizes, and hashes
    Core->>Registry: Acquire matching-attempt finalization lease
    Core->>Store: Atomic artifact finalization
    Core->>Registry: Commit core RunManifest, artifact links, and terminal run state
```

### 14.6 Exit-code categories

| Exit code | Process-level meaning |
|---:|---|
| `0` | Command completed successfully at the process level |
| `10` | Request or schema validation failure |
| `20` | Strategy not applicable to this adapter |
| `30` | Adapter or engine unavailable |
| `40` | Adapter or engine runtime failure |
| `50` | Cancelled |
| `60` | Timed out |
| `70` | Protocol violation detected by the adapter |

Any other exit code maps to a stable `UNRECOGNIZED_PROCESS_EXIT` runtime diagnostic. The core may itself classify a process as timed out, cancelled, or protocol-violating even when forced termination produces a different native Windows exit value.

The exit code is not the semantic result. The validated matching `AdapterResultManifest` is authoritative for what the adapter semantically declares, while the core-generated `RunManifest` is authoritative for the reconciled run record. Terminal success is derived from the adapter semantic declaration, observed or explicitly unknown process exit category, lifecycle and finalization-lease state, and finalized artifacts. A zero exit without a valid adapter result manifest cannot succeed. A valid success declaration with a known nonzero failure exit cannot succeed. On application restart, a fully valid matching candidate from a process whose exit code was lost may be recovered only under section 29 and produces a core `RunManifest` with an unknown-exit warning.

For `validate`, exit `20` maps to `NOT_APPLICABLE`, exit `30` maps to `UNAVAILABLE`, and exit `10` maps to validation failure when the `AdapterValidationResult` agrees. For `run`, a late exit `20` or `30` is accepted only with a matching adapter result manifest carrying the same semantic status and a diagnostic explaining why preflight did not resolve it. The engine-run moves to `NOT_APPLICABLE` or `UNAVAILABLE`; no success artifacts are finalized. A contradictory exit and manifest is a protocol failure.

### 14.7 Protocol limits and contamination

- Stdout is reserved exclusively for protocol JSON Lines. A blank line is a protocol violation, as is unexpected text, invalid UTF-8, malformed JSON, an oversized line, an unknown field or event, or mismatched identity.
- The default maximum encoded event line is 1 MiB. Configuration may lower it but cannot raise it above the compiled safety ceiling without a protocol-version change.
- The default maximum result manifest is 16 MiB. Large results belong in artifacts.
- Stderr is human-readable engine output. It is captured separately, redacted where required, and retained up to 50 MiB per attempt using deterministic bounded segments. Truncation creates a diagnostic and audit event.
- The parser reads incrementally and applies byte limits before JSON decoding.
- On contamination, the core records a bounded escaped sample, requests cancellation, applies the grace period, terminates if necessary, rejects finalization, and records a terminal protocol diagnostic.

Malformed output is never passed through an untyped dictionary into the application layer and is never treated as a warning-only condition when it compromises event framing or identity.

### 14.8 Timeout and cancellation

Every request has an absolute UTC deadline and supervisor monotonic deadline. The monotonic deadline governs local timeout behavior and is immune to wall-clock changes. Heartbeats demonstrate liveness but do not extend the run deadline unless an explicit immutable timeout policy permits a bounded extension recorded in the request.

Cancellation is idempotent. The supervisor records the request, sends a graceful adapter-specific interrupt through the process controller, waits the configured grace period, then force-terminates the verified process tree. A timeout follows the same cleanup path but ends in `TIMED_OUT`; user or orchestrator cancellation ends in `CANCELLED`. A race with successful completion is resolved by a registry compare-and-swap on the active attempt and its finalization lease.

## 15. Process supervision

### 15.1 Start and identity

Before launch, the supervisor:

1. Revalidates the run state, attempt token, executable catalog entry, executable checksum, request hash, and assigned paths.
2. Creates a unique temporary run directory owned by that attempt.
3. Opens bounded stdout and stderr readers before process work begins.
4. Launches the absolute executable with an argument array, explicit working directory, no shell, and a fresh non-inherited environment block. Project 1 fake adapters receive no ambient environment variables; all inputs arrive through validated files and arguments. Future adapter projects may add explicitly configured non-secret runtime entries through a new reviewed contract, but the core never reads parent environment variables as configuration or credentials.
5. Records PID, process-creation identity, executable hash, start time, and supervisor instance ID transactionally with `STARTING` to `RUNNING` progression.

PID alone is insufficient because Windows may reuse it. Process identity combines PID with an operating-system process handle or creation timestamp and the recorded executable path/hash.

### 15.2 Heartbeat and progress

The default expected heartbeat interval is 15 seconds and the default missing-heartbeat threshold is 45 seconds. These are local configuration values snapshotted into the immutable request. A missing heartbeat emits a diagnostic and initiates the configured liveness policy; it does not by itself claim the engine is dead until process identity and I/O state are checked.

Progress is informational and never used to infer success. The supervisor persists state-changing events and bounded summaries while JSON Lines raw protocol output is retained as an artifact subject to size policy.

### 15.3 Windows-compatible termination

The process controller uses Windows process handles and a new process group. It SHOULD attach the child tree to a Windows Job Object with kill-on-close semantics when available. The Job Object is a cleanup mechanism, not a security sandbox. If Job Object attachment is unavailable, the controller verifies descendant identity before best-effort tree termination and records the limitation.

Graceful cancellation defaults to 10 seconds. Forced termination occurs only after the grace period or immediately for a severe protocol/path violation. Cleanup closes handles, stops readers, releases temporary resources, and records all failed cleanup actions as diagnostics.

### 15.4 Path boundary enforcement

Every adapter-supplied path must be relative, normalized, free of drive prefixes, free of alternate data-stream syntax, and free of `..` traversal. The core resolves the candidate against the assigned run root and verifies containment before opening it. It rejects symbolic links, junctions, reparse points, and hard-link surprises that could escape or alias outside the root. Containment is rechecked immediately before validation, hashing, and finalization to reduce time-of-check/time-of-use risk.

The adapter never receives a writable core registry path or finalized-artifact path. Only the assigned temporary directory is writable by contract. Project 1 does not claim this contract is enforced by an operating-system sandbox; therefore only trusted, explicitly registered fake adapters are executed in Project 1.

### 15.5 Restart reconciliation and orphan handling

At core startup, the reconciler scans nonterminal run records:

- `PENDING`, `VALIDATING`, and `READY` can resume idempotently after request and descriptor hashes are revalidated.
- `STARTING` and `RUNNING` require process-identity reconciliation. A `STARTING` attempt never recovers directly to success. If process identity and durable launch facts prove launch completed, reconciliation first compare-and-swap transitions it to `RUNNING`; otherwise it becomes `FAILED` and retry policy applies.
- If the matching process is alive but protocol pipes cannot be safely reattached, the core terminates the verified process tree, records `ORCHESTRATOR_RESTART_LOST_SUPERVISION`, and applies retry policy.
- If no matching process exists, the core examines only the assigned temporary directory for a matching `AdapterResultManifest` and attempt token. Recovery rules in section 29 determine whether finalization may resume.
- Any other live process found by stale PID is left untouched and recorded as a PID-reuse diagnostic.
- Orphan directories and incomplete outputs are quarantined or deleted only through an explicit audited retention action; they are never treated as finalized.

### 15.6 Stale-attempt protection

Each attempt has a unique `run_id`, monotonic `attempt_number`, unguessable `attempt_token`, unique work directory, and registry revision. The adapter echoes the token in every adapter envelope and its `AdapterResultManifest`; the core stores a hash in its authoritative records. Before finalization, the core acquires a short-lived finalization lease with a compare-and-swap proving that the run is still the active nonterminal attempt for its logical slot.

A retry always creates a new run ID, token, and directory. A late event or file from an older attempt fails identity and lease checks. Because adapters cannot write the database or final store, a stale child cannot finalize itself.

## 16. Experiment lifecycle

### 16.1 States and transitions

```mermaid
stateDiagram-v2
    [*] --> DRAFT
    DRAFT --> VALIDATED: canonical validation succeeds
    DRAFT --> CANCELLED: abandon before validation
    VALIDATED --> DRAFT: edit before queueing
    VALIDATED --> QUEUED: freeze spec and enqueue
    VALIDATED --> CANCELLED: abandon before queueing
    QUEUED --> RUNNING: first child slot begins handling
    QUEUED --> FAILED: dispatch cannot begin
    QUEUED --> CANCELLED: cancel before launch
    RUNNING --> COMPLETED: all required outcomes clean
    RUNNING --> COMPLETED_WITH_WARNINGS: usable result with warnings
    RUNNING --> FAILED: no usable result or invariant failure
    RUNNING --> CANCELLED: experiment cancellation wins
    COMPLETED --> [*]
    COMPLETED_WITH_WARNINGS --> [*]
    FAILED --> [*]
    CANCELLED --> [*]
```

| State | Meaning | Allowed next states |
|---|---|---|
| `DRAFT` | Material inputs may still change | `VALIDATED`, `CANCELLED` |
| `VALIDATED` | Inputs and references validate, but may still be deliberately edited | `DRAFT`, `QUEUED`, `CANCELLED` |
| `QUEUED` | Spec is immutable and engine slots are fixed | `RUNNING`, `FAILED`, `CANCELLED` |
| `RUNNING` | At least one selected slot is being resolved, attempted, or retried | `COMPLETED`, `COMPLETED_WITH_WARNINGS`, `FAILED`, `CANCELLED` |
| `COMPLETED` | Required applicable runs succeeded without run or experiment warnings | Terminal |
| `COMPLETED_WITH_WARNINGS` | At least one usable run succeeded and warnings, approximations, partial failures, timeouts, or unavailability require attention | Terminal |
| `FAILED` | No usable result exists or a core invariant/persistence failure prevents trustworthy completion | Terminal |
| `CANCELLED` | Experiment cancellation won before terminal aggregation | Terminal |

Every transition not listed is forbidden. Terminal states never transition. A new execution after terminal completion requires a new experiment, even if the new experiment references the same immutable input hashes.

### 16.2 Immutability

The transaction from `VALIDATED` to `QUEUED` verifies and freezes:

- Strategy version
- Dataset version
- Selected engine slots
- Starting balance
- Fee and slippage assumptions
- Execution and rounding assumptions
- Comparison level
- Configuration snapshot
- Timeout and cancellation policy
- Every other material input

Changing any item creates a new experiment ID and spec hash. Before `QUEUED`, an edit returns the record to `DRAFT` and invalidates the prior validation result.

### 16.3 Child correlation and aggregation

Each selected engine slot has zero or more run attempts. Only the latest valid attempt contributes to aggregate state; predecessor attempts remain immutable history.

Experiment terminal aggregation occurs only after every selected slot has a terminal latest attempt and no retry is pending, scheduled, or still permitted by the immutable retry policy. A retriable terminal child attempt does not by itself terminalize the experiment; the experiment remains `RUNNING` while the successor attempt is created or a retry decision is durably resolved.

- `NOT_APPLICABLE` is an expected compatibility fact and is not a run failure.
- A `NOT_APPLICABLE` result discovered only after `run` starts carries `COMPAT.LATE_NOT_APPLICABLE`; it remains a non-failure compatibility outcome but always contributes an experiment warning because preflight did not predict it.
- `UNAVAILABLE`, `FAILED`, and `TIMED_OUT` are not votes against a strategy.
- If every applicable selected slot succeeds cleanly and every non-applicable slot was expected by deterministic preflight, the experiment is `COMPLETED`.
- If at least one applicable slot succeeds but another applicable slot is unavailable, fails, times out, succeeds with warnings, requires an allowed approximation, or becomes late `NOT_APPLICABLE`, the experiment is `COMPLETED_WITH_WARNINGS`.
- If no slot yields a usable success and at least one applicable slot fails, times out, or is unavailable, the experiment is `FAILED`.
- If every selected slot is `NOT_APPLICABLE`, the experiment is `FAILED` with `NO_APPLICABLE_ENGINE`, because it produced no research result even though no engine crashed.
- If experiment cancellation wins the compare-and-swap before aggregation, the experiment is `CANCELLED`; already finalized artifacts remain preserved and are marked as pre-cancellation results.

Retries of the same immutable experiment occur before the experiment enters a terminal state. Retry policy creates a new child attempt without changing the experiment inputs. Once the experiment is terminal, repeating work requires a new experiment record so terminal-state immutability remains intact.

## 17. Engine-run lifecycle

### 17.1 States and transitions

```mermaid
stateDiagram-v2
    [*] --> PENDING
    PENDING --> VALIDATING: begin compatibility and request validation
    PENDING --> CANCELLED: cancellation before validation
    VALIDATING --> READY: request and runtime validate
    VALIDATING --> NOT_APPLICABLE: semantic incompatibility
    VALIDATING --> UNAVAILABLE: compatible runtime unavailable
    VALIDATING --> FAILED: invalid invariant or internal validation failure
    VALIDATING --> CANCELLED: cancellation wins
    READY --> STARTING: acquire launch lease
    READY --> UNAVAILABLE: runtime disappears before launch
    READY --> CANCELLED: cancellation wins
    STARTING --> RUNNING: process identity recorded
    STARTING --> FAILED: launch failure
    STARTING --> UNAVAILABLE: executable or runtime unavailable
    STARTING --> CANCELLED: cancellation wins
    STARTING --> TIMED_OUT: start deadline exceeded
    RUNNING --> SUCCEEDED: valid clean core RunManifest finalized
    RUNNING --> SUCCEEDED_WITH_WARNINGS: valid core RunManifest finalized with warnings
    RUNNING --> NOT_APPLICABLE: late validated semantic incompatibility
    RUNNING --> UNAVAILABLE: runtime becomes unavailable
    RUNNING --> FAILED: runtime, protocol, artifact, or invariant failure
    RUNNING --> CANCELLED: cancellation wins
    RUNNING --> TIMED_OUT: deadline wins
    SUCCEEDED --> [*]
    SUCCEEDED_WITH_WARNINGS --> [*]
    FAILED --> [*]
    CANCELLED --> [*]
    TIMED_OUT --> [*]
    NOT_APPLICABLE --> [*]
    UNAVAILABLE --> [*]
```

| State | Meaning | Allowed next states |
|---|---|---|
| `PENDING` | Attempt exists but validation has not begun | `VALIDATING`, `CANCELLED` |
| `VALIDATING` | Core compatibility, request, descriptor, and runtime checks are running | `READY`, `NOT_APPLICABLE`, `UNAVAILABLE`, `FAILED`, `CANCELLED` |
| `READY` | Immutable request is valid and runtime was observed available | `STARTING`, `UNAVAILABLE`, `CANCELLED` |
| `STARTING` | Launch lease held and process creation is in progress | `RUNNING`, `FAILED`, `UNAVAILABLE`, `CANCELLED`, `TIMED_OUT` |
| `RUNNING` | Matching child is supervised or matching output is being finalized | `SUCCEEDED`, `SUCCEEDED_WITH_WARNINGS`, `NOT_APPLICABLE`, `UNAVAILABLE`, `FAILED`, `CANCELLED`, `TIMED_OUT` |
| `SUCCEEDED` | Clean matching manifest and artifacts finalized | Terminal |
| `SUCCEEDED_WITH_WARNINGS` | Valid usable result finalized with diagnostics or approximations | Terminal |
| `FAILED` | Runtime, protocol, artifact, persistence, or invariant failure | Terminal |
| `CANCELLED` | Cancellation won and no later finalization is accepted | Terminal |
| `TIMED_OUT` | Deadline won and no later finalization is accepted | Terminal |
| `NOT_APPLICABLE` | Semantic compatibility or adapter-specific validation failed; normally no `run` launched, though a matching late exit `20` may discover it | Terminal |
| `UNAVAILABLE` | Semantic compatibility passed but the runtime could not produce a result; describe/validate may have run, or availability may have disappeared during `run` | Terminal |

All other transitions are forbidden. Each transition records prior state, next state, revision, actor, reason code, timestamp, and correlation ID in the audit log.

### 17.2 Idempotency and retry

- Creating an attempt is idempotent on `(experiment_id, logical_slot_id, attempt_number)`.
- Protocol events are idempotent on `(run_id, sequence)` and identical content hash. A conflicting duplicate is a protocol violation.
- Finalization is idempotent on `(run_id, attempt_token, adapter_result_manifest_hash)` and refuses a different adapter result manifest for the same attempt.
- A retriable failure creates a new run ID and increments attempt number. The new record references its predecessor and retry reason.
- Automatic retries are bounded by the immutable experiment retry policy and never apply to `NOT_APPLICABLE`, policy violations, deterministic schema errors, or artifact corruption without a new source result.
- An `UNAVAILABLE` attempt may be retried only after a new explicit availability observation; it does not become `READY` in place.

### 17.3 Recovery

On restart, nonterminal attempts follow section 15 reconciliation. Terminal attempts are never reopened. A recoverable completed adapter result manifest may finish the original nonterminal attempt only if attempt identity, request hash, `adapter_result_manifest_hash`, artifact checks, and finalization lease all validate. Otherwise the original attempt becomes `FAILED` and any policy-approved retry is a new attempt.

## 18. Dataset registry

Project 1 defines dataset records and registry behavior but does not download, import, or normalize real market data. Tests use committed small fixtures or generated in-memory fixture content that is materialized only in test-controlled temporary directories during later implementation.

### 18.1 Descriptor content

Every immutable dataset version records:

- Dataset ID and SHA-256 content hash
- Source and venue
- Canonical instrument identity
- Data type such as OHLCV, trades, quotes, or Level 2 order book
- Timeframe where applicable
- Inclusive start and exclusive end UTC bounds
- Original timezone and normalization-to-UTC declaration
- Download or import timestamp, when a later project performs ingestion
- Raw-source provenance
- Normalization implementation and version
- Ordered partition list
- Missing intervals
- Duplicate intervals
- Validation status and diagnostics
- Raw checksums
- Normalized checksums
- Column-schema version
- Known limitations

### 18.2 Partition and validation rules

Partitions are immutable Parquet files for large tabular content. Partition boundaries and ordering are deterministic for a given normalization version. Each partition records path, row count, time bounds, schema, raw lineage, normalized checksum, and quality observations.

Validation distinguishes `VALID`, `VALID_WITH_WARNINGS`, and `INVALID`. Missing or duplicate intervals are explicit records, never silently filled or dropped. A strategy or comparison policy determines whether a warning is acceptable. Dataset validity never derives solely from a filename or directory presence.

### 18.3 Registry behavior

- Dataset records are content-addressed but retain operational IDs for references and audits.
- An existing content hash is reused idempotently rather than rewritten.
- A new normalization version creates a new dataset version and hash even when raw source files are unchanged.
- Experiments reference a dataset version hash, not a mutable “latest” alias.
- Raw provenance and normalized content are both preserved in the registry contract.
- Adapters receive read-only dataset references appropriate to their runtime contract in future projects and may not mutate registry-owned data.
- Dataset paths are local registry-relative references subject to the same containment and reparse-point defenses as artifacts.

## 19. Artifact model and immutability

### 19.1 Ownership and classes

The core owns artifact identity, lifecycle, checksums, provenance, and finalization. Adapters produce candidate files only. Artifact classes include:

- Engine-native reports and databases preserved as opaque or typed raw artifacts
- Canonical normalized orders, fills, positions, portfolio snapshots, equity series, and metrics
- Dataset partitions and dataset manifests
- Strategy and configuration snapshots
- Request, event-stream, and result manifests
- Bounded stdout protocol captures and stderr logs
- Diagnostic and comparison reports

The artifact registry uses `CANDIDATE`, `VALIDATING`, `FINALIZING`, `FINALIZED`, `QUARANTINED`, and `CORRUPT`. Only `FINALIZED` artifacts may be referenced by a successful core `RunManifest`. Finalized bytes and their manifest are immutable. Any correction produces a new artifact ID and content hash with provenance linking the superseded record.

### 19.2 Finalization flow

```mermaid
flowchart TD
    Start["Adapter writes candidate in assigned temporary directory"] --> Event["Adapter declares candidate relative path"]
    Event --> Boundary{"Path remains inside assigned root"}
    Boundary -->|"No"| Reject["Reject, diagnose, cancel, and quarantine"]
    Boundary -->|"Yes"| Validate["Validate type, schema, size, and semantic constraints"]
    Validate --> Valid{"Validation succeeds"}
    Valid -->|"No"| Reject
    Valid -->|"Yes"| Hash["Core calculates SHA-256 and size"]
    Hash --> Manifest["Core builds canonical manifest with provenance"]
    Manifest --> Lease{"Matching run and attempt acquire finalization lease"}
    Lease -->|"No"| Reject
    Lease -->|"Yes"| Prepared["Commit PREPARED finalization journal"]
    Prepared --> Move["Atomic move on same volume into finalized content path"]
    Move --> Moved["Commit MOVED journal state"]
    Moved --> Register["Commit artifact records, core RunManifest, and run links"]
    Register --> Final["Artifact is authoritative and immutable"]
    Move -->|"MOVED journal commit interrupted"| Recover["Startup reconciliation finishes registration or quarantines"]
    Moved -->|"Registration interrupted"| Recover
    Recover --> Final
    Recover --> Reject
```

The required sequence is:

1. Temporary output in the unique assigned run directory
2. Path, size, media, schema, and semantic validation
3. Independent SHA-256 checksum calculation
4. Canonical manifest creation
5. Matching-attempt finalization lease acquisition
6. Durable `PREPARED` finalization-journal entry
7. Atomic move into the finalized artifact location on the same volume
8. Durable `MOVED` journal state
9. Transactional artifact registration, core `RunManifest` generation, and run linkage

The final store is content-addressed by SHA-256 under a core-controlled root. The implementation may deduplicate identical immutable blobs, but each logical `ArtifactRef` preserves its own experiment/run provenance and artifact role. Existing finalized content is never overwritten.

### 19.3 Failure and cancellation rules

- A failed, cancelled, timed-out, not-applicable, or unavailable run cannot newly acquire a finalization lease.
- A cancellation or timeout compare-and-swap that wins before finalization invalidates the attempt token for finalization.
- If finalization wins first, the successful or warning result is committed before a later cancellation request is recorded as ineffective.
- A crash before the atomic move leaves only temporary or quarantined output.
- A crash after atomic move but before registry commit leaves a `FINALIZING` recovery fact, not a successful run. Startup reconciliation either verifies and completes the same manifest or moves the content to quarantine.
- Presence in a directory is never sufficient evidence of finalization; artifact registry state, `adapter_result_manifest_hash`, generated `run_manifest_hash`, content hashes, and matching run state must agree.
- Partial files, unexpected files, symlinks, reparse points, and files that change while hashing are rejected.

### 19.4 Manifest rules

A core-generated artifact manifest records artifact ID, kind, media type, relative finalized path, size, hash, schema version, producer identity, source candidate path, experiment/run/attempt identity, source artifact lineage, validation profile, validation diagnostics, and finalization timestamps. The manifest itself is canonical JSON and content-hashed.

The adapter's `AdapterResultManifest` is the final adapter semantic declaration but remains a candidate at the core trust boundary. It references candidate relative paths and claimed hashes, never core-issued artifact IDs. For a successful or successful-with-warnings result, the core validates and stores it, creates authoritative artifact records, reconciles the process outcome, and then generates the core `RunManifest`. A failed, cancelled, timed-out, not-applicable, or unavailable run has no core `RunManifest`; its terminal evidence remains in the run record, diagnostics, audit trail, and quarantine records. The core does not rewrite native engine artifacts to make them appear canonical.

## 20. Result normalization and provenance

### 20.1 Dual preservation

For every successful run, the core preserves:

1. **Engine-native output:** the original report, database export, event log, or files produced by the pinned engine/adapter, stored immutably.
2. **Canonical normalized output:** strictly validated engine-neutral records and tabular series suitable for declared comparison levels.

Canonical conversion never replaces, truncates, or deletes the native source. A successful conversion references its exact source artifact hash. If conversion later improves, the new normalized artifact points to the same native source and a new converter version.

### 20.2 Required provenance

Every normalized record or partition retains:

- Experiment ID and immutable experiment-spec hash
- Run ID and attempt identity
- Engine name and version
- Adapter name and version
- Converter name and version
- Source artifact ID and SHA-256 hash
- Canonical schema version
- Protocol version
- Strategy and dataset version hashes
- Approximation declarations
- Normalization timestamp and validation profile

Provenance may be represented once in a Parquet file manifest when every row shares it, but the association must be unambiguous and protected by the artifact hash.

### 20.3 Normalized result families

Normalized output may include `CanonicalOrder`, `CanonicalFill`, `Fee`, `PositionSnapshot`, `PortfolioSnapshot`, `EquityPoint`, `MetricValue`, and `Diagnostic` records. Large ordered series use versioned Parquet schemas. Small summaries and manifests use JSON.

Metric names alone are insufficient for comparison. A metric records unit, methodology version, sampling convention, comparison level, and undefined status. For example, two “Sharpe ratio” values are not comparable until return frequency, risk-free assumption, annualization, missing-data policy, and methodology version agree.

### 20.4 Difference classification

Cross-engine comparison reports classify differences rather than erase them. Initial difference categories include:

- Input or data alignment
- Warm-up behavior
- Indicator implementation
- Signal timing
- Order timing
- Fee modeling
- Slippage modeling
- Precision or rounding
- Partial-fill behavior
- Portfolio accounting
- Engine-native execution semantics
- Declared approximation
- Normalization limitation
- Unexplained difference

An unexplained difference blocks any claim of parity at the affected level. No result is averaged into a synthetic return and no majority count approves a strategy.

## 21. Error and diagnostic model

### 21.1 Stable structure

Every stored error uses the `Diagnostic` structure and includes:

- `error_code`
- `category`
- `message`
- `source_component`
- `experiment_id` where applicable
- `run_id` where applicable
- `engine` where applicable
- `retriable`
- `timestamp_utc`
- Structured `details`
- Causal diagnostic references where available

Codes are stable uppercase namespaced identifiers such as `CONFIG.UNKNOWN_FIELD`, `SCHEMA.UNSUPPORTED_VERSION`, `COMPAT.MISSING_CAPABILITY`, `ADAPTER.UNAVAILABLE`, `PROTOCOL.STDOUT_CONTAMINATION`, `ARTIFACT.CHECKSUM_MISMATCH`, and `PERSISTENCE.CONCURRENCY_CONFLICT`. Message text may improve without changing code semantics.

### 21.2 Categories

| Category | Examples | Default retry posture |
|---|---|---|
| User or configuration | Invalid path, unsupported comparison level, prohibited live request | Not retriable without changed input, therefore requires a new experiment if already queued |
| Schema validation | Unknown field, invalid Decimal, naive timestamp, unsupported schema | Not retriable with identical input |
| Compatibility | Missing capability, disallowed approximation | `NOT_APPLICABLE`; not retriable with identical requirements and descriptor |
| Adapter unavailability | Missing executable, incompatible version, runtime not configured | Retriable only after a new availability observation |
| Engine runtime | Engine crash, native data error, internal engine failure | Policy-controlled and bounded |
| Protocol | Malformed JSON Lines, wrong attempt token, sequence gap, stdout contamination | Not automatically retriable unless the adapter/runtime changes |
| Timeout | Start, heartbeat, run, cancellation, or finalization deadline | Policy-controlled and bounded |
| Cancellation | User or orchestrator cancellation | Not a failure; retry requires explicit new attempt while experiment remains active |
| Artifact corruption | Size/hash/schema mismatch, unsafe path, mutation during hashing | Not retriable from the same candidate bytes |
| Persistence | Locked database beyond policy, disk full, failed transaction, migration mismatch | Retriable only when idempotency and state reconciliation prove safety |
| Internal invariant | Forbidden transition, mismatched immutable hash, impossible aggregate state | Not automatically retriable; requires investigation |

### 21.2.1 Normative boundary mapping

| Boundary condition | Required diagnostic code and category | Run or experiment effect | Related adapter exit category | Retriable default |
|---|---|---|---|---|
| Prohibited live, credential, network, short, margin, futures, or leverage request | `POLICY.PROHIBITED_OPERATION`, user/configuration | Reject before compatibility; no run attempt | None | False |
| Unknown field, unsupported schema, invalid Decimal, or naive timestamp in request | `SCHEMA.REQUEST_INVALID`, schema validation | `VALIDATING` to `FAILED` when an attempt exists | `10` for adapter-detected request validation | False |
| Missing or disallowed required capability | `COMPAT.NOT_APPLICABLE`, compatibility | `VALIDATING` to `NOT_APPLICABLE` | `20` when adapter `validate` confirms it | False for unchanged inputs |
| Compatible adapter executable/runtime absent or version negotiation empty | `ADAPTER.UNAVAILABLE`, adapter availability | `VALIDATING` or `READY` to `UNAVAILABLE` | `30` | True only after a new availability observation |
| Adapter or engine crashes during run | `ENGINE.RUNTIME_FAILURE`, engine runtime | `STARTING` or `RUNNING` to `FAILED` | `40` | Policy-controlled |
| User or orchestrator cancellation wins | `PROCESS.CANCELLED`, cancellation | Run to `CANCELLED`; experiment aggregation follows cancellation policy | `50` when child cooperates | False without explicit retry decision |
| Start, heartbeat, run, or cancellation deadline wins | `PROCESS.TIMED_OUT`, timeout | Run to `TIMED_OUT` | `60` when child reports it; core may force terminate | Policy-controlled |
| Adapter detects its own protocol violation | `PROTOCOL.ADAPTER_REPORTED_VIOLATION`, protocol | Run to `FAILED` | `70` | False until adapter changes |
| Malformed JSON Lines | `PROTOCOL.MALFORMED_JSONL`, protocol | Cancel/terminate child; run to `FAILED` | Core-derived protocol failure | False until adapter changes |
| Blank or unexpected stdout text | `PROTOCOL.STDOUT_CONTAMINATION`, protocol | Cancel/terminate child; run to `FAILED` | Core-derived protocol failure | False until adapter changes |
| Event too large | `PROTOCOL.EVENT_TOO_LARGE`, protocol | Cancel/terminate child; run to `FAILED` | Core-derived protocol failure | False |
| Wrong run/token or event sequence conflict | `PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION`, protocol | Reject event, terminate child, run to `FAILED` | Core-derived protocol failure | False |
| Candidate path escapes assigned root or is a link/reparse point | `ARTIFACT.PATH_BOUNDARY_VIOLATION`, artifact corruption/security | Reject finalization; run to `FAILED` | None unless adapter also exits nonzero | False |
| Candidate size, schema, or checksum mismatch | `ARTIFACT.VALIDATION_FAILED`, artifact corruption | Quarantine candidate; run to `FAILED` | None | False for identical bytes |
| Manifest missing, oversized, wrong identity, or inconsistent with exit | `ARTIFACT.RESULT_MANIFEST_INVALID`, artifact corruption/protocol | No core `RunManifest`; run to `FAILED` | Reconciled with observed exit | False for identical result |
| SQLite busy timeout or optimistic CAS conflict | `PERSISTENCE.CONCURRENCY_CONFLICT`, persistence | Roll back; retain prior durable state | None | True after state reload |
| Disk full or database write failure | `PERSISTENCE.WRITE_FAILED`, persistence | Roll back registry change; finalization journal drives recovery | None | Conditional after storage repair |
| Forbidden transition or immutable hash mismatch | `CORE.INVARIANT_VIOLATION`, internal invariant | Prevent mutation; fail affected command and run when one exists | None | False |

The core stores native process exit values separately from these stable categories. A boundary condition maps deterministically even when forced Windows termination produces a platform-specific number. More specific codes may be added within a category, but they may not change the state, exit-category reconciliation, or retriable semantics above without a versioned design change.

### 21.3 Exception capture

Free-form exception strings are never the only failure record. At a boundary, an exception is mapped to a stable diagnostic with a bounded sanitized message, component, operation, and causal reference. Full local traceback capture may be stored in a restricted diagnostic artifact when it contains no secrets and remains within retention policy. Tracebacks are not emitted into protocol stdout.

### 21.4 Causal chains and aggregation

Diagnostics form an acyclic causal graph. A run-level terminal diagnostic may reference an adapter event diagnostic, a process-exit diagnostic, and an artifact-validation diagnostic. The experiment-level diagnostic references child diagnostics without copying mutable text. This supports auditability and avoids losing root causes in aggregate status.

## 22. Configuration model

### 22.1 Formats and ownership

- TOML is used for application and local runtime configuration.
- YAML is used only for human-authored portable strategy sources.
- JSON is used for generated manifests, descriptors, requests, protocol events, and small structured artifacts.
- Parquet is used for large tabular datasets and result series.

Configuration models are strict, versioned, and reject unknown fields. The core does not read application configuration, credentials, tokens, or engine settings from environment variables in Project 1.

### 22.2 Deterministic precedence

Configuration is resolved in this order, from lowest to highest precedence:

1. Compiled safe defaults
2. One explicitly named primary TOML file
3. One explicitly named local override TOML file, if supplied
4. Explicit non-secret CLI flags defined by the command schema

There is no automatic directory scan, environment-variable layer, registry layer, remote configuration, or implicit user-profile file. The resolved configuration is validated once, normalized to canonical JSON, hashed, and snapshotted for every queued experiment. CLI flags may control operational actions, but any flag that changes a material run assumption contributes to the experiment spec and configuration hash.

### 22.2.1 Project 1 configuration schema

Relative paths resolve against the directory containing the explicitly supplied primary TOML file. When no file is supplied, they resolve against the explicit invocation base directory passed by the composition root. Path resolution never consults an environment variable or implicit user-profile location.

| Key | Type, default, and bounds | Material run hash | Permitted CLI override |
|---|---|---:|---|
| `paths.runtime_root` | Local path, default `runtime` | No; included in application audit hash | Yes, explicit path only |
| `paths.data_root` | Local path, default `data` | Dataset content identity is material; display root is not | Yes, explicit path only |
| `paths.artifacts_root` | Local path, default `artifacts`; must share a volume with runtime staging | No; artifact hashes and identities are material | Yes, explicit path only |
| `paths.logs_root` | Local path, default `logs` | No | Yes, explicit path only |
| `paths.runtimes_root` | Local path, default `runtimes`; catalog executables must remain explicit | No; executable hash/version are material | Yes, explicit path only |
| `database.filename` | Safe filename, default `crypto_lab.sqlite3`, resolved under runtime root | No | No |
| `database.busy_timeout_ms` | Integer, default `5000`, range `100` through `60000` | No | No |
| `scheduler.max_concurrent_runs` | Integer, default `1`, range `1` through `8` | No; value is audited per experiment | Yes |
| `process.heartbeat_interval_seconds` | Integer, default `15`, range `1` through `300` | Yes | Yes |
| `process.missing_heartbeat_seconds` | Integer, default `45`, range `2` through `900`, and at least twice heartbeat interval | Yes | Yes |
| `process.default_run_timeout_seconds` | Integer, default `3600`, range `1` through `604800` | Yes | Yes |
| `process.cancellation_grace_seconds` | Integer, default `10`, range `0` through `300` | Yes | Yes |
| `protocol.max_event_bytes` | Integer, default and ceiling `1048576`; may be lowered to at least `4096` | Yes | No |
| `protocol.max_manifest_bytes` | Integer, default and ceiling `16777216`; may be lowered to at least `65536` | Yes | No |
| `logging.max_stderr_bytes_per_attempt` | Integer, default `52428800`, range `1048576` through `52428800` | Yes because truncation affects evidence | No |
| `logging.retained_files` | Integer, default `10`, range `1` through `100` | No | No |
| `adapters.entries` | Explicit ordered list of adapter name/version, absolute executable path, executable hash, and non-secret fixed runtime metadata; default empty | Selected entry identity is material | No ad hoc executable override |
| `policy.allow_network` | Fixed `false` in Project 1 | Yes | No |
| `policy.allow_credentials` | Fixed `false` in Project 1 | Yes | No |
| `policy.allow_live` | Fixed `false` in the approved product scope | Yes | No |

The canonical run-configuration hash covers every row marked material plus selected adapter and engine identities, fee/slippage/execution assumptions, dataset/strategy hashes, and comparison level. A separate application audit hash covers the complete normalized configuration, including operational paths and concurrency, so local behavior remains explainable without making machine-specific paths economic inputs.

Project 1 child processes receive a fresh environment block rather than inheriting the parent's block. The Project 1 adapter catalog permits no environment entries. Absolute executable paths, request paths, output paths, and working directories are passed as arguments. A future adapter needing non-secret fixed environment entries requires its own reviewed adapter design; ambient inheritance and environment-based credentials remain prohibited.

### 22.3 Configuration boundaries

Core configuration may contain local roots, retention limits, heartbeat policy, timeouts, SQLite settings, adapter catalog paths, and logging policy. An adapter catalog entry may describe an explicit executable and non-secret runtime metadata. Portable strategies and experiment records MUST NOT contain credentials or secret references.

Future credential support, if ever approved for a different product scope, belongs behind a dedicated security boundary outside engine-neutral domain models and portable strategy specifications. It does not become an environment-variable fallback in this core.

### 22.4 Safety policy

The configuration validator rejects:

- `runtime.live`
- Real-order or withdrawal endpoints
- Credential fields
- Short, margin, futures, or leverage settings outside the approved scope
- Shell command strings
- Network-enabled behavior not explicitly supported by a future policy version
- Writable adapter paths outside assigned runtime and temporary roots

Safe defaults disable all adapter execution until an explicit catalog entry and fake-adapter test configuration are supplied.

### 22.5 Windows storage prerequisites

The runtime staging root and finalized artifact root MUST be on the same local fixed NTFS volume so finalization can use an atomic rename. Configuration validation fails before queueing if volume identity differs, either root is a network share, or a root is a reparse point. Dataset storage may occupy another local volume because it is not part of run-artifact atomic finalization.

The platform adapter probes supported path behavior without changing global Windows settings. If long-path support is unavailable, preflight rejects any derived path that would exceed the conservative supported ceiling. If long paths are supported, the implementation uses path APIs that preserve absolute identity. Tests for long-path success are conditional on detected support; tests for deterministic preflight rejection always run. Project 1 does not request administrator changes or enable Windows features.

## 23. Persistence model

### 23.1 Database role

SQLite is the authoritative local metadata and state registry. It stores identities, immutable specs, lifecycle states, descriptors, hashes, provenance, diagnostics, audits, and artifact references. Large tabular content and engine-native files stay outside SQLite as immutable artifacts.

SQLite runs in WAL mode with foreign keys enabled and a bounded busy timeout. The durability baseline uses `synchronous=FULL` for authoritative state transitions. Any later performance relaxation requires a recorded architecture decision and crash-consistency evidence.

### 23.2 SQLAlchemy and units of work

SQLAlchemy 2.x provides explicit mapped persistence models and session boundaries. Domain Pydantic models remain distinct from ORM models. Mapping code validates on both ingress and egress so database rows cannot bypass canonical invariants.

Application services operate through repository protocols and a `UnitOfWork`. One unit of work owns one short transaction. It commits only after all invariant checks succeed and rolls back on any exception. Long adapter execution, file hashing, and subprocess waiting never occur inside an open SQLite write transaction.

Optimistic concurrency uses a `revision` column and compare-and-swap updates. A transition that affects zero rows is a stable concurrency conflict, not permission to overwrite newer state.

### 23.3 Registry aggregates and constraints

Planned persistence aggregates include:

- Schema and migration metadata
- Strategy versions and extension hashes
- Dataset descriptors and partitions
- Experiments and immutable specs
- Engine slots, run attempts, process facts, and finalization leases
- Run events and heartbeats
- Artifact records, manifests, and provenance edges
- Metrics and normalized-result indexes
- Diagnostics and causal references
- Audit events

Key constraints include unique operational IDs, unique content identities where deduplication is valid, unique `(experiment_id, logical_slot_id, attempt_number)`, unique `(run_id, event_sequence)`, immutable spec hash after queueing, foreign-key ownership, and exactly one active finalization lease per logical slot.

### 23.3.1 Normative table and transaction map

Query-critical identities, states, revisions, timestamps, hashes, and foreign keys use typed columns. Immutable canonical snapshots and bounded event payloads use canonical JSON text plus a SHA-256 column. Large series and native output never become database blobs.

| Table or aggregate | Primary identity and ownership | Required relations and delete behavior | Required indexes and transaction boundary |
|---|---|---|---|
| `strategy_versions` | Strategy-version hash; core-owned immutable canonical JSON | Strategy ID is retained as value; deletion is restricted while any experiment references the hash | Unique hash and `(strategy_id, created_at_utc)`; one registration transaction |
| `datasets` | `dataset_id` plus unique content hash | Owns partitions; deletion is restricted while referenced by an experiment or artifact | Unique content hash and instrument/time bounds index; registration transaction covers descriptor metadata |
| `dataset_partitions` | `partition_id`; owned by one dataset | Foreign key to dataset with restricted delete; artifact reference is restricted | Unique `(dataset_id, ordinal)` and checksum index |
| `experiments` | `experiment_id`; owns immutable canonical spec JSON, spec hash, state, revision | Strategy/dataset hashes must resolve; delete is restricted after queueing | State/created index and unique spec identity only when deduplication policy explicitly requests it; every state CAS is one transaction |
| `engine_slots` | `logical_slot_id`; owned by one experiment | Foreign key to experiment with restricted delete | Unique `(experiment_id, ordinal)` and adapter/engine lookup index |
| `engine_runs` | `run_id`; owned by one slot and experiment | Predecessor run is a restricted self-reference; deletes are restricted once any invocation, event, diagnostic, or artifact exists | Unique `(logical_slot_id, attempt_number)`, state index, active-attempt partial uniqueness, and revision CAS |
| `command_invocations` | `invocation_id`; owned by adapter command and optional run | Run foreign key required for validate/run and restricted on delete | `(run_id, command_kind, started_at_utc)` and process-identity index; start and completion facts use separate short transactions |
| `run_events` | Composite `(run_id, sequence)` | Foreign key to run with restricted delete | Unique event ID and received-time index; one idempotent append transaction per accepted event |
| `artifact_records` | `artifact_id`; core-owned lifecycle and immutable finalized metadata | Experiment/run/source-artifact foreign keys use restricted delete | Content hash, state, run/role, and finalized path indexes; state CAS protects finalization |
| `run_artifacts` | Composite `(run_id, artifact_id, role)` | Both foreign keys restricted; links never cascade-delete evidence | Role and artifact indexes; committed with core `RunManifest` registration |
| `run_manifests` | Core manifest ID and unique `run_manifest_hash` | One terminal core manifest per successful run; `adapter_result_manifest_hash` required | Unique run ID for terminal success; inserted with artifact links and terminal transition |
| `diagnostics` | `diagnostic_id`; core-owned immutable fact | Optional experiment/run links use restricted delete; causal edges live in a separate restricted join table | Error code, category, severity, experiment, run, and timestamp indexes |
| `audit_events` | `audit_event_id`; append-only | Optional entity references do not cascade; evidence remains after retention of non-authoritative logs | Correlation, experiment, run, action, and timestamp indexes; append joins the action transaction when possible |
| `finalization_journal` | `finalization_id`; one active entry per run attempt and `adapter_result_manifest_hash` | References run and adapter result candidate; paths are core-controlled relative paths | State, lease expiry, and run index; `PREPARED`, `MOVED`, `REGISTERED`, or `QUARANTINED` state is committed at each durability boundary |

The finalization journal durably bridges filesystem and database operations:

1. A short transaction validates the active attempt, acquires the lease, and inserts `PREPARED` with run ID, attempt-token hash, `adapter_result_manifest_hash`, staging path, intended final path, lease owner, acquired UTC, expiry UTC, and revision.
2. Outside a database transaction, the core revalidates files and performs the atomic same-volume move.
3. A short transaction changes the journal to `MOVED` and records observed finalized hashes and paths.
4. One transaction inserts artifact records and links, generates the core `RunManifest`, moves the run terminal, and changes the journal to `REGISTERED`.
5. Startup reconciliation handles any durable intermediate state. A journal entry never expires directly into success; the reconciliation lease and full validation are required.

Foreign-key delete behavior is `RESTRICT` for authoritative evidence. Retention operates through explicit audited commands and may remove only unreferenced temporary/log data under policy. No relational cascade may erase an experiment's run, artifact, diagnostic, or audit history.

### 23.4 Migrations

Alembic migrations are explicit and ordered. Startup checks the database revision before normal commands. An unsupported newer database revision blocks startup without mutation. Upgrades require an explicit local migration command, backup guidance, and migration tests. Destructive migration steps preserve exportable provenance or require a separate approved data-migration design.

Canonical JSON and Parquet schema migrations are separate from relational migrations and have their own versioned converters and tests.

### 23.5 Adapter prohibition

Adapters and engines receive neither SQLite credentials nor the writable database path. They do not import persistence models, open the registry, or rely on database file layout. All state mutation occurs through validated protocol input returned to the core. Engine-native databases, if produced later, are preserved as artifacts and never become the system of record.

## 24. Security model

### 24.1 Fixed safety statements

Project 1 enforces the following statements:

- No real trading
- No exchange credentials
- No API-key handling
- No withdrawal functionality
- No live-order API
- No short, margin, futures, or leveraged execution
- No arbitrary shell strings
- No `shell=True` or equivalent
- No implicit network access
- No automatic plugin discovery from untrusted paths
- No direct adapter access to the registry database
- No adapter writes outside its assigned working directory by contract
- No secrets in strategy files, experiment records, manifests, logs, diagnostics, or artifacts
- No engine output trusted without schema and boundary validation
- No deserialization of arbitrary Python objects or pickle files across trust boundaries
- No Docker use and no server deployment

### 24.2 Local threat model

The intended operator and central installation are trusted local components. Strategy/configuration mistakes, malformed files, faulty adapters, engine crashes, stale processes, path traversal, output contamination, and accidental secret leakage are considered credible threats. A deliberately malicious executable with the user's operating-system permissions is outside Project 1's containment guarantee.

Process isolation is a reliability boundary. Strict paths, explicit executable registration, checksums, safe parsing, bounded I/O, and minimal process inputs are defense-in-depth. They are not described as operating-system sandboxing.

### 24.3 Input and output controls

- YAML uses safe parsing and a declarative allowlisted expression grammar.
- TOML, JSON, JSON Lines, and Parquet are validated against expected versioned schemas before use.
- Unknown fields are rejected at process and artifact boundaries.
- File paths are normalized and confined; links and reparse escapes are rejected.
- Event, manifest, stderr, and artifact sizes are bounded before expensive processing.
- Logs and diagnostics use field-level redaction and never record future credentials.
- Adapter outputs cannot request core code imports, shell execution, database access, or arbitrary destination paths.
- Content hashes are independently recalculated by the core.

### 24.4 Network and live vocabulary

Descriptors declare whether a future runtime requires network access or credentials. Project 1 fake adapters declare both false. Such a descriptor may be represented for future compatibility analysis, but Project 1 policy rejects any operation that would require network access, credentials, or live execution. The existence of `runtime.live` in capability vocabulary is not a feature flag, executable path, or approval.

## 25. Cross-engine comparison levels

Comparison level is an immutable experiment input. A run or approximation that cannot satisfy the requested level is excluded from that level rather than coerced.

### 25.1 Level 1 — Signal parity

Level 1 compares deterministic strategy intent:

- Indicator and feature values
- Entry signals
- Exit signals
- Eligible symbols
- Position-sizing intent

Inputs use the same normalized bars, warm-up boundaries, feature-semantics version, parameter values, universe, and Decimal rules. Execution fills and portfolio accounting are outside Level 1. Differences are aligned by instrument, bar timestamp, feature/rule ID, and source row.

### 25.2 Level 2 — Bar-execution parity

Level 2 requires Level 1 plus:

- Same normalized candle data and partition hashes
- Same timezone and bar-boundary convention
- Same warm-up period
- Same initial balance
- Same fee assumptions
- Same slippage assumptions
- Same signal-to-order timing
- Same position-sizing rules
- Same instrument precision and rounding rules
- Same bar-order priority and fill convention

Level 2 compares canonical orders, fills, positions, equity, and methodology-compatible metrics. Any engine behavior that cannot be configured or normalized to these assumptions is an explicit approximation and may prevent Level 2 eligibility.

### 25.3 Level 3 — Native execution realism

At Level 3, each engine uses its strongest appropriate native execution model for the declared experiment. Results are not expected to be numerically identical. Engine-native reports remain central evidence, and differences are classified by execution, fill, fee, portfolio, precision, or modeling semantics.

Level 3 results:

- Are presented side by side with provenance and assumptions
- Are never averaged into a synthetic return
- Are never reduced to majority voting
- Do not establish strategy promotion automatically
- Must identify known approximations and unexplained differences

### 25.4 Comparison eligibility

The comparison service checks dataset hash, strategy hash, configuration assumptions, schema versions, methodology versions, and approximation declarations before aligning results. A run can be valid by itself yet ineligible for comparison with another run. Ineligibility is a structured result, not data deletion or retroactive run failure.

`ComparisonEligibilityService` is a pure service owned by `experiments/comparison.py`. It accepts two core `RunManifest` records and a requested level, then returns `ELIGIBLE`, `INELIGIBLE`, or `ELIGIBLE_WITH_DECLARED_DIFFERENCES` plus stable reasons. It performs no metric averaging and mutates no run. A separate later report projection may align eligible canonical artifacts, but the Project 1 core only defines and tests eligibility and difference classification.

## 26. Seven-engine future integration matrix

This matrix is a **planned adapter intent**, not a statement of verified current framework capability. Every entry MUST be tested against a pinned engine version, its official documentation, and local contract tests during the named adapter project. “Likely” and “expected” describe design hypotheses only.

| Engine | Planned adapter project | Expected primary role | Likely native capability intent | Likely approximations | Expected runtime isolation | Expected result-adapter responsibilities | Strategy classes likely `NOT_APPLICABLE` |
|---|---:|---|---|---|---|---|---|
| VectorBT Community | Project 3 | Fast bar-based screening and parameter research | Vectorized OHLCV research, signal arrays, broad parameter exploration | Bar-order timing, intra-bar execution, partial fills, and portfolio details may require simplified models | Dedicated pinned Python runtime launched as a child process | Map portable features and signals, preserve native arrays/reports, emit canonical signals/equity/metrics, declare execution simplifications | Order-book, maker-order, event-driven microstructure, and multi-venue execution strategies |
| Freqtrade | Project 4 | Primary Binance candle backtesting and dry-run reference | Binance-oriented candle strategies, long spot workflows, backtest and future dry-run behavior | Exact portable sizing, fee/slippage conventions, signal timing, and native lifecycle hooks may require adaptation | Dedicated pinned Python runtime and explicit data/config workspace | Translate portable bar rules, normalize trades/orders/equity, preserve native reports, document dry-run versus backtest semantics | Level 2 order-book, market-making, arbitrage, equities, and unsupported multi-venue strategies |
| NautilusTrader | Project 5 | Event-driven and execution-model validation | Event-driven data and execution modeling, richer order/fill lifecycle, multi-instrument intent | Portable bar-rule mapping and engine-specific precision/timing choices may differ from simple bar engines | Dedicated pinned Python/native runtime in a child process | Map canonical requests to native event models, normalize orders/fills/positions, preserve event traces, classify execution differences | Pure vectorized parameter sweeps or strategy forms that cannot map to its adapter contract |
| Jesse | Project 6 | Research, optimization, robustness, and Monte Carlo analysis | Candle research, strategy evaluation, and robustness workflows | Portable feature/rule lifecycle, optimization semantics, and portfolio assumptions may require adapter-specific mapping | Dedicated pinned Python runtime | Preserve native research reports, normalize signal and execution series, represent robustness outputs as typed artifacts, declare methodology | Order-book market making, multi-venue arbitrage, equities, and strategies needing unsupported event detail |
| OctoBot | Project 7 | Independent bot workflow and paper-mode comparison | Bot-oriented strategy lifecycle and future simulated operation | Portable bar parity, sizing, portfolio accounting, and lifecycle hooks may need explicit approximations | Dedicated pinned Python runtime with its own local workspace | Map declared strategy intent, preserve bot-native state/reporting, normalize fills/equity, separate paper-mode behavior from canonical wallet semantics | Strategies whose deterministic rules cannot be expressed through the pinned adapter, plus unsupported equities or microstructure cases |
| Hummingbot | Project 8 | Order-book, market-making, and arbitrage research | Maker-order, Level 2, multiple-order, and multi-venue research intent | Candle-only portable rule translation, portfolio normalization, and cross-venue timing may require approximations | Dedicated pinned client/runtime process with explicit local files | Normalize order-book-driven orders/fills, preserve native logs/config snapshots, record venue/time synchronization limits | Deterministic bar strategies lacking a verified adapter mapping, equities, and unsupported single-venue candle workflows |
| QuantConnect LEAN | Project 9 | Multi-asset validation and future Indian-equities pathway | Multi-asset/event-driven research and equities pathway | Binance-specific candle conventions, fee/slippage models, symbol mapping, and local data formats may differ | Separate pinned .NET/LEAN runtime invoked through an executable adapter | Map canonical instruments and datasets, preserve native result packets/reports, normalize orders/fills/portfolio series, document model choices | Engine-specific bot workflows, unsupported exchange dry-run behavior, and strategy extensions tied to another runtime |

Before any adapter becomes runnable, its project MUST pin versions, produce a validated `AdapterDescriptor`, verify operating-system support, verify network and credential requirements, enumerate known modeling limitations, and pass the Project 1 contract suite. A mismatch between this planned matrix and verified behavior updates the descriptor and design record; it does not get hidden by adapter code.

## 27. Planned repository structure

Project 1 plans the following structure but this documentation task does not create it:

```text
src/crypto_lab/
  domain/
  strategy/
  capabilities/
  adapters/
  experiments/
  datasets/
  artifacts/
  persistence/
  process_supervision/
  configuration/
  audit/
  cli/

schemas/
  strategy/
  protocol/
  artifacts/

tests/
  unit/
  contract/
  integration/
  property/
  fixtures/
  fake_adapters/

docs/
  superpowers/
    specs/
    plans/
  architecture/
  decisions/

runtime/       generated and Git-ignored
data/          generated and Git-ignored
artifacts/     generated and Git-ignored
logs/          generated and Git-ignored
runtimes/      generated and Git-ignored
```

### 27.1 Central package responsibilities

| Package | Responsibility | Allowed inward dependencies | Prohibited dependencies |
|---|---|---|---|
| `domain` | Canonical records, identifiers, Decimal/time primitives, enums, hashes, state-transition tables, and invariant errors | Python standard library and Pydantic model primitives | Adapters, persistence, subprocess APIs, configuration readers, CLIs, engine libraries |
| `strategy` | Safe YAML source loading, strategy models, expression grammar, feature DAG validation, canonicalization, and strategy versioning | `domain` | Engines, persistence implementations, subprocesses, arbitrary execution |
| `capabilities` | Vocabulary definitions, requirement/declaration validation, approximation rules, and pure deterministic resolver | `domain` | Runtime launch, persistence implementations, engine imports |
| `adapters` | Descriptor, request, event, manifest, command, exit-category, and negotiation contracts; explicit adapter catalog interface | `domain` | Trading-engine packages, shell execution, concrete persistence |
| `experiments` | Application services, experiment/run state coordination, slot aggregation, retry policy, and repository ports | `domain`, `strategy`, `capabilities`, `adapters`, `datasets`, `artifacts`, `process_supervision`, `audit` abstractions | Concrete SQLAlchemy sessions, engine packages, direct process APIs |
| `datasets` | Dataset registry application service, partition validation contracts, dataset hashing profile, and repository ports | `domain` | Exchange clients in Project 1, engines, concrete persistence |
| `artifacts` | Candidate validation, path confinement, hashing, manifests, finalization leases, atomic moves, provenance, and repository ports | `domain` | Engines, implicit paths, adapter-owned databases |
| `persistence` | SQLAlchemy mappings, SQLite repositories, unit of work, query projections, Alembic integration, and persistence recovery | `domain` plus application-owned repository protocols | Engines and adapter executables |
| `process_supervision` | Windows-compatible process controller, incremental protocol reader, stderr capture, heartbeat/deadline handling, cancellation, and restart reconciliation | `domain`, `adapters`, `audit` abstractions | Engine imports, shell strings, economic strategy logic |
| `configuration` | Strict TOML models, deterministic precedence, safe defaults, policy validation, canonical snapshots, and hashes | `domain` | Environment-variable configuration, credentials, engines |
| `audit` | Diagnostic factory, redaction, JSON Lines logging contracts, append-only audit interface, and correlation context | `domain` | Engine packages and mutable global state |
| `cli` | Local command definitions and composition root wiring abstract ports to concrete implementations | All application-facing packages as required for composition | Business rules duplicated from application/domain layers, engine imports, live-order commands |

The dependency direction table is normative. When composition requires a concrete class, only `cli` or a dedicated composition module imports that implementation. Application modules receive interfaces through constructors or explicit functions.

### 27.2 Planned module map

The later implementation plan can decompose packages along these boundaries:

- `domain/identifiers.py`, `financial.py`, `time.py`, `records.py`, `states.py`, `diagnostics.py`, `canonical_json.py`, and `hashing.py`
- `strategy/models.py`, `yaml_loader.py`, `expressions.py`, `feature_graph.py`, `validation.py`, and `versioning.py`
- `capabilities/vocabulary.py`, `models.py`, `resolver.py`, and `policy.py`
- `adapters/descriptors.py`, `envelopes.py`, `events.py`, `manifests.py`, `exit_codes.py`, `negotiation.py`, and `catalog.py`
- `experiments/models.py`, `ports.py`, `state_machine.py`, `run_state_machine.py`, `service.py`, `scheduler.py`, `aggregation.py`, `comparison.py`, and `retry.py`
- `datasets/models.py`, `ports.py`, `validation.py`, `hashing.py`, and `service.py`
- `artifacts/models.py`, `ports.py`, `paths.py`, `validation.py`, `manifest.py`, `finalizer.py`, and `recovery.py`
- `persistence/mappings.py`, `repositories.py`, `unit_of_work.py`, `database.py`, and Alembic migration integration
- `process_supervision/models.py`, `windows_process.py`, `protocol_reader.py`, `stderr_capture.py`, `supervisor.py`, and `reconciliation.py`
- `configuration/models.py`, `loader.py`, `precedence.py`, `policy.py`, and `snapshot.py`
- `audit/models.py`, `redaction.py`, `jsonl.py`, `sink.py`, and `correlation.py`
- `cli/main.py`, command modules, and `composition.py`

This is a responsibility map, not code created by this specification task. An implementation plan may split a listed module when cohesion or test isolation requires it, but it MUST preserve the package boundaries and dependency direction.

### 27.3 Non-package directories

| Directory | Responsibility and rule |
|---|---|
| `schemas/strategy` | Generated and reviewed JSON Schemas for portable strategy versions |
| `schemas/protocol` | Generated request, event, descriptor, negotiation, and result-manifest schemas |
| `schemas/artifacts` | Generated schemas and Parquet schema declarations for canonical artifacts |
| `tests/unit` | Pure model, resolver, hash, configuration, and state-machine tests |
| `tests/contract` | Executable adapter protocol compliance tests |
| `tests/integration` | Core workflow tests with fake adapters and temporary storage |
| `tests/property` | Generative invariant, round-trip, hashing, and path-boundary tests |
| `tests/fixtures` | Small deterministic non-secret input and expected-output fixtures |
| `tests/fake_adapters` | Purpose-built executable test doubles covering success and failure protocols |
| `docs/superpowers/specs` | Approved design specifications |
| `docs/superpowers/plans` | Future implementation plans created only after explicit user review and approval |
| `docs/architecture` | Stable architecture explanations derived from approved specifications |
| `docs/decisions` | Focused architecture decision records for later approved changes |
| `runtime` | Generated SQLite files, locks, temporary runs, and reconciliation state; Git-ignored |
| `data` | Generated/imported datasets and partitions; Git-ignored |
| `artifacts` | Finalized immutable artifact store; Git-ignored |
| `logs` | Bounded local JSON Lines and human-readable diagnostic logs; Git-ignored |
| `runtimes` | Isolated future engine environments and executable catalogs; Git-ignored |

Runtime directories are never Python packages and never a source of automatic plugin discovery.

## 28. Testing strategy

Project 1's test suite uses fake adapters only. It does not install, import, execute, or require VectorBT Community, Freqtrade, NautilusTrader, Jesse, OctoBot, Hummingbot, or QuantConnect LEAN. Tests run offline and use temporary directories for generated state.

### 28.1 Unit tests

Unit tests cover:

- Every canonical domain validation rule and unknown-field rejection
- Financial `Decimal` parsing, normalization, precision, sign, and non-finite rejection
- UTC timestamp acceptance, RFC 3339 `Z` serialization, and naive datetime rejection
- Instrument identity parsing and canonical reconstruction
- Every allowed and forbidden experiment transition
- Every allowed and forbidden engine-run transition
- Terminal-state immutability and optimistic-concurrency conflicts
- Capability vocabulary validation and deterministic compatibility resolution
- Approximation policy and comparison-level exclusion
- Canonical JSON and SHA-256 determinism
- Strategy hashing independent of YAML comments and key ordering
- Engine-extension hash inclusion
- Dataset manifest and partition hashing
- Configuration precedence, unknown-key rejection, and prohibited safety settings
- Experiment immutability at `QUEUED`
- Child-run aggregation and retry bounds
- Diagnostic causal-chain acyclicity and redaction

### 28.2 Contract tests

Contract tests execute fake adapter binaries or scripts through the real supervisor boundary and cover:

- Adapter `describe` contract
- Adapter `validate` contract
- Adapter `run` contract
- Exact exit-code mapping for `0`, `10`, `20`, `30`, `40`, `50`, `60`, and `70`
- Unrecognized native exit-code mapping
- Protocol-version negotiation
- Schema-version negotiation
- Capability-vocabulary negotiation
- Request hash and attempt-token validation
- Event-envelope validation and sequence rules
- Heartbeat, progress, warning, diagnostic, artifact-produced, and final-result events
- `AdapterResultManifest` validation, core `RunManifest` generation, and semantic/process-status reconciliation
- Stdout reservation and stderr separation
- Event and manifest size ceilings

The contract harness becomes the reusable acceptance suite for every future engine adapter project.

### 28.3 Integration tests with fake adapters

Integration scenarios include:

- Successful run
- Successful run with warnings
- `NOT_APPLICABLE`
- `UNAVAILABLE`
- Adapter crash
- Malformed JSON Lines
- Unexpected standard-output text
- Invalid UTF-8 output
- Sequence gap and conflicting duplicate event
- Wrong run ID or stale attempt token
- Missing heartbeat
- Run timeout
- Graceful cancellation
- Forced termination after grace period
- Corrupted artifact
- Unsafe artifact path or reparse-point escape
- Artifact mutation during hashing
- Missing manifest
- Oversized manifest
- Duplicate final event
- Exit zero with no valid manifest
- Nonzero failure exit with a claimed success manifest
- Adapter candidate that improperly claims core artifact IDs
- Retry after restart
- Stale child output after retry
- Crash before artifact move
- Crash after artifact move before registry commit
- Partial child success and experiment warning aggregation
- All selected engines not applicable
- SQLite optimistic-concurrency conflict and idempotent replay

Each scenario asserts database state, lifecycle history, audit records, diagnostics, temporary/final artifact state, and child-process cleanup.

### 28.4 Property-based tests

Property-based tests cover:

- Decimal JSON round trips across valid magnitude and scale ranges
- UTC timestamp round trips and rejection of noncanonical forms
- Canonical hash determinism under object-key permutation
- Model serialization and schema round trips
- State-machine forbidden transitions for arbitrary state pairs
- Compatibility-result determinism under capability input ordering
- Path-boundary validation across separators, traversal segments, drive syntax, Unicode, links, and reparse metadata
- Run-event sequence idempotency
- Artifact finalization idempotency
- Experiment-spec hash sensitivity to every material input

Generated inputs are bounded so failures produce minimal reproducible examples without large local artifacts.

### 28.5 Windows platform tests

Windows-specific tests cover:

- Repository and work paths containing spaces
- Unicode path components
- Long paths under supported Windows configuration
- Argument-array preservation without shell interpretation
- Child-process group and handle cleanup
- Graceful and forced termination
- PID reuse protection through creation identity
- Atomic same-volume finalization behavior
- File-lock and open-handle failures
- Reparse-point and junction rejection
- SQLite WAL restart recovery
- Orchestrator restart with nonterminal run records

### 28.6 Acceptance evidence

The implementation test command, type checker, schema-generation check, migration check, and package build command will be defined by the later implementation plan. Project 1 is not accepted by a green unit suite alone; all test classes above and the generated-schema diff check must pass offline.

## 29. Recovery and durability

### 29.1 Durability principles

- Registry state transitions are transactional, short, and protected by foreign keys and optimistic revisions.
- SQLite WAL and `synchronous=FULL` are the baseline for authoritative local state.
- Large immutable files are checksum-protected and atomically moved only on the same volume.
- A process event is not equivalent to a durable terminal transition.
- A terminal transition is not committed until required artifact and manifest invariants hold.
- Every recovery action is idempotent and audited.

### 29.2 Startup reconciliation order

On every core startup, before new runs are launched:

1. Verify application configuration and safety policy.
2. Verify database revision and SQLite integrity checks appropriate to normal startup.
3. Acquire the single local reconciliation lease.
4. Reconcile `FINALIZING` artifact records and pending filesystem moves.
5. Reconcile `STARTING` and `RUNNING` process records using PID plus creation identity.
6. Validate any matching candidate result manifest in the assigned temporary directory.
7. Resume safe finalization, terminate unverifiable live children, or mark failed with diagnostics.
8. Requeue only idempotent pre-launch states and policy-approved new attempts.
9. Quarantine orphan temporary directories and unregistered finalized content.
10. Release the reconciliation lease and permit normal scheduling.

The reconciler never attaches an arbitrary directory to a run based on naming alone and never kills a process based solely on PID.

### 29.3 Recovering a completed candidate

A run left `RUNNING` after core failure may recover an `AdapterResultManifest` candidate only when:

- No matching child process remains active.
- The manifest is inside the assigned directory and under the size ceiling.
- Run ID, experiment ID, attempt token, request hash, adapter, engine, and versions match registry facts.
- The semantic status is successful or successful-with-warnings.
- Every referenced artifact passes path, size, schema, and independent checksum validation.
- No cancellation, timeout, newer attempt, or terminal transition won before the recovery lease.
- Finalization is idempotent for the same `adapter_result_manifest_hash`; core registration separately verifies the deterministic `run_manifest_hash`.

Because the native process exit code may have been lost, a recovered success becomes `SUCCEEDED_WITH_WARNINGS` with `RECOVERY.PROCESS_EXIT_UNKNOWN`. A failure manifest or invalid candidate becomes `FAILED`; it is never repaired into success by inference.

### 29.4 Persistence and disk failure

Disk-full, permission, lock-timeout, checksum, and atomic-move failures produce stable diagnostics and leave the run non-successful. The core does not delete the only candidate copy during failed finalization. Retention cleanup is a separate audited action and does not run while an artifact is referenced by an active lease.

Local backup and restore tooling belongs to later implementation planning, but any backup design MUST include the SQLite database, migration revision, finalized artifact store, schemas, and configuration snapshots in a mutually consistent checkpoint. Cloud backup is not assumed.

### 29.5 Idempotent commands

Application commands carry a correlation or idempotency key. Repeating a create, transition, event-ingest, or finalization command either returns the prior identical outcome or a stable conflict. It never creates duplicate experiments, duplicate attempt numbers, duplicate events, or divergent artifacts silently.

## 30. Observability and auditability

### 30.1 Structured local logging

Core logs use JSON Lines with a versioned log schema. Each record includes timestamp, severity, component, event code, correlation ID, experiment ID, run ID, engine/adapter where applicable, message, and bounded structured details. Human-facing console output is a projection of structured facts, not the only record.

Logs are local, bounded, and rotated deterministically. Project 1 sends no telemetry to cloud services and performs no implicit network export. Retention limits are explicit TOML configuration snapshotted in audit events.

### 30.2 Correlation

One correlation context follows a local command through experiment service, repository transactions, process supervision, event ingestion, artifact finalization, diagnostics, and audit events. Run-event sequence numbers and audit-event IDs provide local ordering; UTC timestamps support human reconstruction but do not replace sequence or transaction facts.

### 30.3 Audit events

Append-only audit events are required for:

- Strategy and dataset version registration
- Experiment creation, validation, edits before queueing, queue freeze, and every lifecycle transition
- Compatibility decisions and approximation acceptance
- Run-attempt creation, launch, retry, cancellation, timeout, and terminal transition
- Adapter descriptor registration and version negotiation
- Protocol violations and stderr truncation
- Artifact validation, finalization, quarantine, corruption, and retention deletion
- Database migration and reconciliation actions
- Safety-policy rejection
- Configuration snapshot and hash selection

Audit records capture facts and outcomes, not secrets or mutable exception dumps.

### 30.4 Diagnostics for beginner-friendly operation

Every terminal failure exposes a concise user message, stable code, likely corrective category, retriable flag, and local evidence references. Messages distinguish strategy incompatibility, missing runtime, engine crash, protocol defect, timeout, artifact corruption, and core invariant failure. The CLI does not present all non-success outcomes as “backtest failed.”

### 30.5 Run evidence bundle

A future local command may render an evidence bundle from existing records without mutating them. The bundle includes immutable input hashes, versions, compatibility decision, approximations, lifecycle timeline, process outcome, manifest, artifacts, metrics, diagnostics, and audit references. Project 1 defines the data required for this bundle but does not create a dashboard.

## 31. Rejected alternatives

### 31.1 One shared Python environment for all engines

Rejected because engines may require incompatible Python and dependency versions. A shared environment makes upgrades coupled, failures harder to attribute, and reproducibility dependent on accidental package resolution. The core uses Python 3.12 with `uv`; every engine gets an isolated pinned runtime.

### 31.2 Importing all engines into the orchestrator process

Rejected because native crashes, global state, incompatible dependencies, import side effects, and memory leaks would compromise the core. The adapter executable boundary provides replaceability and failure isolation.

### 31.3 Engine-native databases as the system of record

Rejected because schemas and lifecycle semantics vary by engine and version. The core owns canonical registry state and preserves engine-native databases only as immutable source artifacts.

### 31.4 Comparing engines only by total return

Rejected because total return hides data alignment, signal timing, fees, slippage, precision, execution, and portfolio-accounting differences. Comparison levels and normalized evidence make differences diagnosable.

### 31.5 Majority-vote strategy approval

Rejected because engines are not independent voters and may share assumptions or approximations. Agreement does not prove correctness, and disagreement is valuable evidence. Strategy promotion is outside Project 1.

### 31.6 Arbitrary Python strategy code inside the core process

Rejected because it defeats determinism, static validation, portability, hashing, and the security boundary. Version 1 strategies are declarative; explicit extensions run only inside named future adapter runtimes.

### 31.7 Docker as a required runtime

Rejected because the product is local Windows software and Project 1 neither uses nor requires Docker. Engine isolation is defined by executable processes and isolated runtimes. Any future optional packaging proposal requires a new approved design and cannot be introduced as an implementation detail.

### 31.8 Cloud-first infrastructure

Rejected because the product is personal and local-only, and cloud services would add credentials, networking, operational cost, privacy exposure, and failure modes outside current goals.

### 31.9 Paper wallet before canonical contracts

Rejected because wallet accounting would otherwise depend on unstable order, fill, fee, instrument, and lifecycle semantics. The paper wallet follows the canonical contracts in a later project.

### 31.10 All seven adapters before protocol stability

Rejected because framework-specific code would force premature coupling and make contract defects expensive to correct. Fake adapters stabilize core behavior first; real adapters then arrive as separately verified projects.

## 32. Future project boundaries

The following sequence expresses planned boundaries, not implementation authorization:

| Project | Boundary |
|---:|---|
| Project 1 | Engine-neutral canonical core, contracts, registries, subprocess supervision, persistence, artifact lifecycle, and fake-adapter tests described here |
| Project 2 | Local historical market-data ingestion and normalization for approved Binance Spot USDT data, implementing the Project 1 dataset contracts without exchange credentials |
| Project 3 | VectorBT Community adapter against a pinned verified version |
| Project 4 | Freqtrade adapter against a pinned verified version |
| Project 5 | NautilusTrader adapter against a pinned verified version |
| Project 6 | Jesse adapter against a pinned verified version |
| Project 7 | OctoBot adapter against a pinned verified version |
| Project 8 | Hummingbot adapter against a pinned verified version |
| Project 9 | QuantConnect LEAN adapter against a pinned verified version and future Indian-equities compatibility study |
| Project 10 | Canonical risk controls and always-available hypothetical-money wallet and paper-trading orchestration |
| Project 11 | Indian tax-adjusted performance and TDS analysis using finalized canonical results and explicit policy versions |
| Project 12 | Local dashboard and beginner-friendly workflow over existing application services |
| Project 13 | Local LLM analysis over immutable evidence bundles after deterministic foundations are reliable |

Each adapter project reuses the Project 1 contract suite, verifies the matrix hypotheses, pins runtime and framework versions, and records deviations. It does not weaken core ownership or import engine code into the orchestrator.

Live trading, exchange credentials, withdrawal functionality, cloud deployment, and server deployment are not assigned to a future project in the approved scope. Adding one would require a new product decision and security architecture rather than an incremental adapter change.

## 33. Acceptance criteria

Project 1's future implementation is acceptable only when all of the following are demonstrated with fresh offline evidence:

### 33.1 Architecture and boundaries

- The central runtime is Python 3.12, strictly typed, and managed with `uv`.
- No real trading engine is installed, imported, or required by the Project 1 test suite.
- The domain layer has no dependency on adapters, persistence, subprocess APIs, engine libraries, or the CLI.
- Every adapter operation is an isolated child process invoked by an argument array without a shell.
- Only explicit adapter catalog entries can run; arbitrary directory discovery is absent.
- The core is the sole writer and system of record for experiments, runs, artifacts, datasets, diagnostics, and audits.

### 33.2 Canonical contracts

- All required records in section 11 exist as strict Pydantic v2 canonical models with generated versioned JSON Schemas.
- Unknown fields are rejected at process and artifact boundaries.
- Authoritative financial values use `Decimal` and canonical JSON strings; binary floating point is absent from authoritative financial fields.
- Canonical timestamps require timezone-aware UTC and serialize with `Z`; naive datetimes fail validation.
- Operational IDs use validated prefixes and UUID4 values.
- Strategy, dataset, configuration, extension, manifest, and finalized-file hashes are deterministic SHA-256 values.
- Explicit migrations preserve earlier immutable representations and provenance.

### 33.3 Strategy, capability, and comparison

- Safe YAML validates into the versioned declarative `StrategySpec` without arbitrary code execution.
- Version 1 supports deterministic bar-based feature graphs, entry/exit rules, sizing intent, risk assumptions, warm-up, comparison requirements, approximation policy, and explicit extension declarations.
- Capability vocabulary includes every item listed in section 13.
- Compatibility resolution is deterministic and produces only the four approved outcomes with complete reasons.
- `SUPPORTED_WITH_APPROXIMATION` always carries machine-readable impact and comparison-level exclusions.
- `NOT_APPLICABLE` and `UNAVAILABLE` remain distinct and are not counted as strategy failures.
- Level 1, Level 2, and Level 3 eligibility rules are enforced; no majority vote or synthetic return averaging exists.
- Any `runtime.live` request is rejected by core policy.

### 33.4 Protocol and supervision

- `describe`, `validate`, and `run` contracts pass the fake-adapter contract suite.
- Request, event, heartbeat, progress, warning, diagnostic, artifact-produced, final-result, and manifest schemas are versioned and negotiated.
- Exit categories `0`, `10`, `20`, `30`, `40`, `50`, `60`, and `70` map exactly as specified.
- A zero exit without a valid matching `AdapterResultManifest` cannot succeed, and only the core can create the consolidated `RunManifest`.
- Stdout contamination, malformed JSON Lines, oversized events, sequence errors, wrong tokens, crashes, missing heartbeat, timeout, graceful cancellation, and forced termination produce the specified states and diagnostics.
- Windows paths with spaces, long paths, process cleanup, PID reuse, and restart reconciliation pass platform tests.
- The implementation does not claim operating-system-level sandboxing.

### 33.5 State, persistence, and durability

- Every allowed lifecycle transition succeeds and every forbidden transition fails atomically.
- Experiments are immutable at and after `QUEUED`; material changes require a new experiment.
- Retries create new run attempts with new IDs, tokens, and directories while retaining immutable predecessor history.
- Stale events and stale children cannot finalize a newer attempt.
- SQLite runs in WAL mode with foreign keys, migrations, explicit units of work, and optimistic concurrency.
- Adapters cannot write the core database.
- Restart reconciliation handles every nonterminal state and finalization crash point without false success.

### 33.6 Data, artifacts, provenance, and audit

- Dataset descriptors record all required provenance, interval-quality, checksum, partition, and limitation fields without downloading real data in Project 1.
- Artifact finalization follows temporary output, validation, core checksum, manifest, matching-attempt lease, atomic move, and authoritative registration.
- Failed, cancelled, timed-out, stale, unavailable, and not-applicable attempts cannot leave an artifact that appears finalized.
- Engine-native output is preserved whenever canonical normalization succeeds or fails.
- Every normalized record links to experiment, run, source artifact, engine, adapter, and schema provenance.
- Errors use stable machine-readable diagnostics rather than free-form exceptions alone.
- JSON Lines logs and audit events are bounded, correlated, local-only, and free of secrets.

### 33.7 Security and exclusions

- There is no live-order API, credential model, API-key handling, withdrawal behavior, implicit network access, arbitrary shell string, pickle boundary, or automatic untrusted plugin discovery.
- There is no Binance API integration, real market-data download, real backtest, paper wallet, tax/TDS logic, risk engine, dashboard, LLM, cloud deployment, Docker use, server deployment, strategy optimization, or promotion logic in Project 1.
- All seven engines appear only as future adapter intents and are not claimed as verified or installed.
- The complete Project 1 suite passes offline using fake adapters only.

## 34. Glossary

| Term | Definition |
|---|---|
| Adapter | A future engine-specific executable that implements the versioned `describe`, `validate`, and `run` contract outside the core process |
| Adapter catalog | Explicit local registry of approved adapter executable paths, versions, hashes, and non-secret runtime metadata |
| Adapter result manifest | Adapter-produced final semantic declaration containing candidate relative paths and claimed hashes; it remains untrusted until core validation |
| Approximation | A declared, versioned substitution for a capability an engine does not provide with the required native semantics |
| Artifact | An immutable validated file plus authoritative metadata, checksum, provenance, and lifecycle state |
| Attempt token | Unguessable correlation nonce for one run attempt; it is not an authentication secret or exchange credential, is redacted from logs, and is hashed in authoritative core records |
| Canonical | Engine-neutral, strictly validated, versioned representation owned by the core |
| Capability | Namespaced vocabulary item describing market, direction, data, execution, portfolio, research, or runtime semantics |
| Comparison level | Declared parity contract: signal intent at Level 1, normalized bar execution at Level 2, or native execution realism at Level 3 |
| Content hash | SHA-256 digest over bytes produced by an explicit canonicalization and hashing profile |
| Dataset version | Immutable normalized dataset descriptor and ordered partition set identified by content hash |
| Engine | One of the external research or trading frameworks integrated only in a future isolated runtime |
| Engine run | One operational attempt by one adapter for one immutable experiment slot |
| Experiment | Immutable-at-queue collection of strategy, dataset, engines, assumptions, comparison level, and configuration used to produce and compare runs |
| Finalization lease | Short-lived compare-and-swap authority permitting only the active matching attempt to finalize artifacts and terminal state |
| Native artifact | Original engine-produced output preserved without being replaced by canonical conversion |
| `NOT_APPLICABLE` | The engine cannot model one or more required semantics; this is not an execution failure |
| Portable strategy | Declarative versioned YAML strategy whose validated economic intent can be mapped to compatible adapters |
| Protocol event | One validated versioned JSON object occupying exactly one stdout line from an adapter |
| Run manifest | Core-generated authoritative consolidated record that reconciles the adapter result manifest, process outcome, finalized artifacts, diagnostics, and provenance |
| Strategy version | Immutable canonical strategy content, hashing profile, and declared extension hashes identified by SHA-256 |
| System of record | The authoritative source for identity, state, provenance, and finalization; in this architecture it is always the core registries and artifact store |
| `UNAVAILABLE` | The adapter is logically compatible but absent, misconfigured, version-incompatible, or not runnable |

This specification ends at the Project 1 design boundary. Implementation planning begins only after explicit user review and approval of this committed document.
