"""The supervised SQLite composition of Stage 8 plan section 7.1.2 (Task 7).

``SupervisedSqliteFlow`` is a test-support composition helper: it drives the
eight selected Stage 6 scenario rows through the production
``WindowsProcessSupervisor`` with every persistence-dependent component bound to
one migrated SQLite test database. It re-composes, in test code, what the Stage 7
in-memory strategy composes over the in-memory store -- lifecycle, request
material, command paths, command, tee controller, recording observer,
cancellation token, supervisor, ``invoke``, then the parse and semantic-outcome
epilogue -- with the storage seam replaced by the binding table of plan 7.1.2:
``SqliteUnitOfWork`` under the Task 6 ``CountingUnitOfWork`` beneath every
application operation and the lifecycle, ``SqliteDiagnosticRecorder``, the Task 3
and 4 writers and repositories through the counted transaction's ``sqlite()``
members, and ``SqliteReconciliationSource`` for the reopen case. It is not a
production service, not a replacement supervisor, not a second protocol parser or
semantic reconciler, and not a subclass of the Stage 6 harness: it imports no
``contract.harness`` class, constructs no in-memory store, unit of work, seeding
recorder or reconciliation source, and reaches no ``.store``.

What it reuses unchanged: the Stage 6 scenario table (``contract.scenarios``),
the fake executable and its launch identities (``supervised_catalog_entry_for``),
the canonical builders (``doubles.experiments`` and the plan 7.1.1 fence), the
command-path contract (``plan_command_paths``) and the production supervision and
application components. Process-local state stays where its contract puts it:
the supervisor's monotonic clock, the observers' traces, the cancellation token,
the parser state and the raw attempt token the request material needs.

Transaction boundaries (plan 7.1.2): the flow opens a counted transaction only
for the registry writes, the freeze, the observation and owner-row write and
closes each before the next step; every application operation owns its
``run_operation`` transaction; the lifecycle's transactions are per call; no
transaction is open while ``invoke`` awaits the child -- a second recording
observer samples ``counting.open_now`` at ``LAUNCHED``, ``RUNNING_COMMITTED``,
``EVENT_ACCEPTED``, ``HEARTBEAT_MISSED`` and ``EXIT_REAPED`` and keeps the
maximum as ``max_open_during_child``. Every authoritative read is a fresh
session (``fresh_read``); the independent stdlib connection counts rows and the
checkpointed main file is hashed for the memory-bound control.

Declared readings, recorded in the Task 7 ledger: ``database_sha256`` runs
``PRAGMA wal_checkpoint(TRUNCATE)`` through the independent connection under
asserted quiescence (no counted transaction open, no pooled connection checked
out) and checks the checkpoint's result before hashing the main file (ledger
A7-01/B7-01); ``conclude`` re-reads the run's and the invocation's stored
revisions before ``apply_command_semantic_outcome`` (B7-03); the candidate
observer hands ``token_present`` the token's UTF-8 bytes (B7-04); S-1 registers
the ``ADAPTER``-owned owner row beside the observation (B7-07).
"""

from __future__ import annotations

import asyncio
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from pydantic.experimental.missing_sentinel import MISSING
from sqlalchemy.pool import QueuePool

from contract.harness import (
    DEFAULT_NEGOTIATED,
    FAKE_OPERATING_SYSTEM,
    FAKE_RUNTIME_VERSION,
    OBSERVATION_VALIDITY,
)
from contract.scenarios import SCENARIOS, Scenario
from crypto_lab.adapters.catalog import AdapterCatalogEntry
from crypto_lab.adapters.commands import AdapterCommand
from crypto_lab.adapters.envelopes import (
    DescribeRequestPayload,
    request_hash_of,
    request_material_hash,
)
from crypto_lab.adapters.events import ProtocolEventSummary, RunEvent
from crypto_lab.adapters.limits import (
    MAX_DESCRIPTOR_OUTPUT_BYTES,
    MAX_VALIDATION_RESULT_BYTES,
    PROTOCOL_LIMITS_DEFAULT,
)
from crypto_lab.adapters.manifests import (
    AdapterResultManifest,
    ManifestParse,
    parse_result_manifest,
    parse_validation_result,
)
from crypto_lab.adapters.negotiation import (
    CORE_PROTOCOL_SUPPORT,
    describe_availability_observation,
    parse_bootstrap_descriptor,
)
from crypto_lab.adapters.reconciliation import (
    CandidateObservation,
    SemanticReconciliation,
    reconcile_describe,
)
from crypto_lab.adapters.sanitization import token_present
from crypto_lab.artifacts.ownership import AdapterArtifactOwner, ArtifactOwnerRef
from crypto_lab.configuration.models import ApplicationConfig
from crypto_lab.configuration.snapshot import ConfigSnapshot
from crypto_lab.datasets.models import DatasetDescriptor
from crypto_lab.domain.command_invocation import (
    CommandInvocationRecord,
    ProcessIdentity,
)
from crypto_lab.domain.descriptors import RuntimeAvailabilityObservation
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.engine_run import AttemptTokenMaterial, EngineRunRecord
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)
from crypto_lab.experiments.invocation_service import (
    create_invocation,
    enrich_invocation,
)
from crypto_lab.experiments.requests import (
    AttemptCreationRequest,
    InvocationCreationRequest,
    InvocationEnrichmentRequest,
    RunTransitionRequest,
    SemanticOutcomeRequest,
)
from crypto_lab.experiments.run_service import create_attempt, transition_run
from crypto_lab.experiments.semantic_outcome import (
    SemanticOutcome,
    apply_command_semantic_outcome,
)
from crypto_lab.experiments.supervision_lifecycle import (
    RequestMaterial,
    Stage5InvocationLifecycle,
)
from crypto_lab.persistence.database import ConsistencyReport, SqliteDatabase
from crypto_lab.persistence.reconciliation_source import SqliteReconciliationSource
from crypto_lab.persistence.registries import SqliteDiagnosticRecorder
from crypto_lab.persistence.unit_of_work import SqliteTransaction, SqliteUnitOfWork
from crypto_lab.process_supervision.cancellation import ThreadSafeCancellationToken
from crypto_lab.process_supervision.models import (
    FORCED_TERMINATION_EXIT_CODE,
    ProcessPresence,
    ReconciliationReport,
    SupervisionOutcome,
    SupervisionTraceEntry,
    SupervisionTraceKind,
)
from crypto_lab.process_supervision.reconciliation import reconcile_invocations
from crypto_lab.process_supervision.roots import (
    CommandPaths,
    PathPreflight,
    plan_command_paths,
)
from crypto_lab.process_supervision.windows_process import WindowsProcessController
from crypto_lab.strategy.versioning import StrategyVersion
from doubles.experiments import (
    AVAIL_A,
    INSTANT,
    SLOT_A,
    FixedClock,
    SequentialIdentitySource,
)
from doubles.supervision import (
    SCRIPTED_SUPERVISOR_INSTANCE_ID,
    RealtimeMonotonicClock,
    RecordingObserver,
    TeeController,
    build_supervisor,
    supervised_catalog_entry_for,
)
from persistence_support.fixtures import supervised_draft
from persistence_support.harness import (
    REASON,
    CountingUnitOfWork,
    commit,
    engine_of,
    file_sha256,
    fresh_read,
    ok,
    open_test_database,
    queue_through_freeze,
    raw_connection,
    run_states_of,
    sample_dataset_with_partitions,
    sample_strategy_version,
)

__all__ = ["DescribeOutcome", "SupervisedSqliteFlow"]

_C: Final = CommandInvocationState
_K: Final = CommandKind
_R: Final = EngineRunState
_T: Final = SupervisionTraceKind
#: Plan 7.1.2: the trace points at which the sampler reads the live transaction
#: count; the maximum over them is ``max_open_during_child``.
_SAMPLED_KINDS: Final = (
    _T.LAUNCHED,
    _T.RUNNING_COMMITTED,
    _T.EVENT_ACCEPTED,
    _T.HEARTBEAT_MISSED,
    _T.EXIT_REAPED,
)
#: Plan 7.1.2: the seven Stage 6 rows the composition drives (S-8 adds no row).
_SUPERVISED_ROW_NAMES: Final = frozenset(
    {
        "row01-conformant-describe",
        "row02-conformant-validate",
        "row03-conformant-run",
        "row05-unsupported-capability-validate",
        "row28-exit-40-run",
        "row27-cancellation-run",
        "row26-process-timeout-run",
    }
)
_SCENARIO_BY_NAME: Final[dict[str, Scenario]] = {item.name: item for item in SCENARIOS}
_CHECKPOINT_SQL: Final = "PRAGMA wal_checkpoint(TRUNCATE)"
_QUICK_CHECK_SQL: Final = "PRAGMA quick_check"
_USER_TABLES_SQL: Final = (
    "SELECT name FROM sqlite_master WHERE type = 'table' "
    "AND name NOT LIKE 'sqlite_%' ORDER BY name"
)
_INVOCATION_COUNT_SQL: Final = (
    "SELECT COUNT(*) FROM command_invocations WHERE invocation_id = ?"
)
_EVENT_COUNT_SQL: Final = "SELECT COUNT(*) FROM run_events WHERE invocation_id = ?"
#: The preflight shape the Stage 7 restart tests build for a reconciliation pass.
_DIRECTORY_CEILING: Final = 247
_FILE_CEILING: Final = 259


@dataclass(frozen=True, slots=True)
class DescribeOutcome:
    """S-1's products: the outcome, the reconciliation, the minted observation
    persisted through the writer and the hash of the registered owner row."""

    outcome: SupervisionOutcome
    reconciliation: SemanticReconciliation
    observation: RuntimeAvailabilityObservation
    owner_hash: str


def _observe_candidates(
    work_dir: Path, summary: ProtocolEventSummary, parse: Any, token: str
) -> tuple[CandidateObservation, ...]:
    """Stage 6 plan 11.3 item 4: the union of event-declared and (for a success
    manifest) manifest-declared paths, observed where the file exists under the
    work directory; the token check receives the token's bytes (B7-04)."""
    declared: list[str] = [
        record.payload.relative_path for record in summary.artifact_declarations
    ]
    if isinstance(parse, ManifestParse) and isinstance(
        parse.manifest, AdapterResultManifest
    ):
        manifest = parse.manifest
        if manifest.semantic_status.value in ("SUCCEEDED", "SUCCEEDED_WITH_WARNINGS"):
            declared.extend(
                item.relative_path
                for item in manifest.candidate_artifacts
                if item.relative_path not in declared
            )
    encoded = token.encode("utf-8")
    observations: list[CandidateObservation] = []
    for relative_path in declared:
        candidate = work_dir.joinpath(*relative_path.split("/"))
        if not candidate.is_file():
            continue
        content = candidate.read_bytes()
        observations.append(
            CandidateObservation(
                relative_path=relative_path,
                observed_size_bytes=len(content),
                observed_sha256=sha256_bytes(content),
                contains_attempt_token=token_present((content,), encoded),
            )
        )
    return tuple(observations)


class SupervisedSqliteFlow:
    """Plan 7.1.2: the eight supervised rows over one SQLite test database.

    The database lives at ``tmp_path / "db" / "registry.sqlite3"``; the
    supervision root is the sibling ``tmp_path / "supervision"``, so no command
    root, work directory, request or output path lies under the database
    directory and the fake adapter receives only ``AdapterCommand`` paths under
    the supervision root -- never the database path or a handle.
    """

    def __init__(
        self,
        database: SqliteDatabase,
        config: ApplicationConfig,
        *,
        clock: FixedClock,
        supervision_root: Path,
    ) -> None:
        self.database = database
        self.config = config
        self.clock = clock
        self.supervision_root = supervision_root
        self._identity = SequentialIdentitySource("stage8-supervised")
        self._root = SqliteUnitOfWork(database, clock)
        self.counting = CountingUnitOfWork(self._root)
        self.recorder = SqliteDiagnosticRecorder(database, clock=clock)
        self.lifecycle = Stage5InvocationLifecycle(
            unit_of_work=self.counting, clock=clock, diagnostics=self.recorder
        )
        self._monotonic = RealtimeMonotonicClock(INSTANT)
        self._tokens: dict[str, str] = {}
        self._paths: dict[str, CommandPaths] = {}
        self._entries: dict[str, AdapterCatalogEntry] = {}
        self._tees: list[TeeController] = []
        self._max_open_during_child = 0
        launcher = Path(sys.executable)
        self._launcher_path = str(launcher)
        self._launcher_hash = sha256_bytes(launcher.read_bytes())

    @classmethod
    def open(cls, tmp_path: Path, *, config: ApplicationConfig) -> SupervisedSqliteFlow:
        """Migrate ``tmp_path / "db"`` and compose the flow over it."""
        clock = FixedClock(INSTANT)
        directory = tmp_path / "db"
        directory.mkdir(exist_ok=True)
        supervision_root = tmp_path / "supervision"
        supervision_root.mkdir(exist_ok=True)
        return cls(
            open_test_database(directory, clock=clock),
            config,
            clock=clock,
            supervision_root=supervision_root,
        )

    @classmethod
    def reopen(cls, tmp_path: Path) -> SupervisedSqliteFlow:
        """S-8: the same file through ``open_test_database`` with new objects only."""
        return cls.open(tmp_path, config=ApplicationConfig())

    def close(self) -> None:
        """Terminate and await anything a controller launched (the Stage 7
        discipline), roll back anything left open, dispose the engine, drop the
        command roots and every application object."""
        try:
            self._assert_nothing_launched_survives()
        finally:
            try:
                leaked = self._root.open_transactions()
                for transaction in leaked:
                    transaction.rollback()
                assert not leaked, "a flow-owned transaction leaked past its finalizer"
            finally:
                self.database.close()
            for paths in self._paths.values():
                shutil.rmtree(paths.command_root, ignore_errors=True)
            self._tees.clear()
            self._paths.clear()
            self._entries.clear()
            self._tokens.clear()

    # -- bookkeeping ----------------------------------------------------------

    @staticmethod
    def scenario(name: str) -> Scenario:
        """One of the seven selected Stage 6 rows, by its ``Scenario.name``."""
        assert name in _SUPERVISED_ROW_NAMES, name
        return _SCENARIO_BY_NAME[name]

    @property
    def max_open_during_child(self) -> int:
        """The greatest ``counting.open_now`` the sampler saw during the last
        ``invoke`` at the five sampled trace points."""
        return self._max_open_during_child

    @property
    def max_open(self) -> int:
        return self.counting.max_open

    @property
    def open_now(self) -> int:
        return self.counting.open_now

    def _fresh[T](self, read: Callable[[SqliteTransaction], T]) -> T:
        return fresh_read(self.database, self.clock, read)

    def _token_for(self, run_id: str) -> str:
        token = self._tokens.get(run_id)
        assert token is not None, "the flow holds no attempt token for the run"
        return token

    def command_root_of(self, invocation_id: str) -> Path:
        """The command root ``plan_command_paths`` assigned to an invoked command,
        for the Stage 7 pre-handoff cleanup assertion (the root is gone by design)."""
        return Path(self._paths[invocation_id].command_root)

    # -- durable setup --------------------------------------------------------

    def _register(self) -> tuple[StrategyVersion, DatasetDescriptor]:
        """Register the two fixture records (idempotent for identical records) in
        one counted transaction and prove the fresh ``get_by_hash`` round trips."""
        version = sample_strategy_version()
        descriptor, partitions = sample_dataset_with_partitions()
        transaction = self.counting.begin()
        try:
            members = transaction.sqlite()
            ok(members.strategy_versions.register(version))
            ok(members.datasets.register(descriptor, partitions))
            commit(transaction)
        finally:
            transaction.rollback()
        stored_version = self._fresh(
            lambda opened: ok(
                opened.strategy_versions.get_by_hash(version.content_hash)
            )
        )
        assert stored_version == version
        stored_descriptor = self._fresh(
            lambda opened: ok(opened.datasets.get_by_hash(descriptor.content_hash))
        )
        assert stored_descriptor == descriptor
        return version, descriptor

    def _transition(
        self,
        run: EngineRunRecord,
        target: EngineRunState,
        *,
        availability_observation_id: str | None = None,
    ) -> EngineRunRecord:
        payload: dict[str, object] = {
            "schema_version": "1.0.0",
            "run_id": run.run_id,
            "expected_revision": run.revision,
            "target_state": target,
            "reason_code": REASON,
        }
        if availability_observation_id is not None:
            payload["availability_observation_id"] = availability_observation_id
        return ok(
            transition_run(
                RunTransitionRequest.model_validate(payload),
                unit_of_work=self.counting,
                clock=self.clock,
            )
        )

    def prepare_run(self, row: Scenario) -> EngineRunRecord:
        """Registries, experiment (freeze, queue), attempt 1 and the pre-child run
        edges: ``VALIDATING`` for a ``VALIDATE`` row, ``READY`` citing ``AVAIL_A``
        for a ``RUN`` row (A7-02; S-1 must have persisted that observation)."""
        assert row.command is not _K.DESCRIBE, "a describe has no run"
        version, descriptor = self._register()
        draft = supervised_draft(
            self.config,
            row.adapter_name,
            strategy_version_hash=version.content_hash,
            dataset_version_hash=descriptor.content_hash,
        )
        queued = queue_through_freeze(
            self.counting,
            clock=self.clock,
            identity=self._identity,
            draft=draft,
            config=self.config,
        )
        creation = ok(
            create_attempt(
                AttemptCreationRequest(
                    schema_version="1.0.0",
                    experiment_id=queued.experiment_id,
                    logical_slot_id=SLOT_A,
                    expected_experiment_revision=queued.revision,
                    request_hash=request_material_hash(
                        experiment=queued,
                        logical_slot_id=SLOT_A,
                        attempt_number=1,
                        negotiated=DEFAULT_NEGOTIATED,
                        limits=PROTOCOL_LIMITS_DEFAULT,
                    ),
                ),
                unit_of_work=self.counting,
                clock=self.clock,
                identity_source=self._identity,
            )
        )
        token = creation.attempt_token
        assert isinstance(token, AttemptTokenMaterial), "attempt 1 mints a token"
        # The raw token lives in the flow's memory for the request material only.
        self._tokens[creation.attempt.run_id] = token.attempt_token
        run = self._transition(creation.attempt, _R.VALIDATING)
        if row.command is _K.RUN:
            run = self._transition(run, _R.READY, availability_observation_id=AVAIL_A)
        return self.fresh_run(run.run_id)

    # -- the supervisor -------------------------------------------------------

    def _invoke(self, row: Scenario, run: EngineRunRecord | None) -> SupervisionOutcome:
        kind = row.command
        entry = supervised_catalog_entry_for(row.adapter_name)
        request: dict[str, object] = {
            "schema_version": "1.0.0",
            "command_kind": kind,
            "adapter_name": entry.adapter_name,
            "adapter_version": entry.adapter_version,
            "timeout_seconds": row.timeout_seconds,
        }
        run_id: Any = MISSING
        if run is None:
            payload = DescribeRequestPayload(
                bootstrap_schema_version="1.0.0",
                adapter_name=entry.adapter_name,
                adapter_version=entry.adapter_version,
                executable_hash=entry.executable_hash,
                core_supported_protocol_versions=CORE_PROTOCOL_SUPPORT.protocol_versions,
                core_supported_schema_versions=CORE_PROTOCOL_SUPPORT.schema_versions,
                core_capability_vocabulary_versions=(
                    CORE_PROTOCOL_SUPPORT.vocabulary_versions
                ),
            )
            request["request_hash"] = request_hash_of(payload)
            material = RequestMaterial(describe_payload=payload)
        else:
            request["run_id"] = run.run_id
            request["expected_run_revision"] = run.revision
            request["request_hash"] = run.request_hash
            material = RequestMaterial(
                token=AttemptTokenMaterial(
                    run_id=run.run_id, attempt_token=self._token_for(run.run_id)
                ),
                negotiated_versions=DEFAULT_NEGOTIATED,
                limits=PROTOCOL_LIMITS_DEFAULT,
            )
            run_id = run.run_id
        invocation = ok(
            create_invocation(
                InvocationCreationRequest.model_validate(request),
                unit_of_work=self.counting,
                clock=self.clock,
                identity_source=self._identity,
            )
        )
        self.lifecycle.register_request_material(invocation.invocation_id, material)
        paths = plan_command_paths(
            str(self.supervision_root),
            command_kind=kind,
            invocation_id=invocation.invocation_id,
            run_id=run_id,
        )
        command_payload: dict[str, object] = {
            "command_kind": kind,
            "catalog_entry": entry,
            "invocation_id": invocation.invocation_id,
            "request_path": paths.request_path,
            "timeout_seconds": row.timeout_seconds,
        }
        if kind is _K.RUN:
            command_payload["work_dir"] = paths.work_dir
            command_payload["result_path"] = paths.result_path
        else:
            command_payload["output_path"] = paths.output_path
        command = AdapterCommand.model_validate(command_payload)
        tee = TeeController(WindowsProcessController())
        observer = RecordingObserver()
        sampler = RecordingObserver()
        cancellation = ThreadSafeCancellationToken()
        self._max_open_during_child = 0

        def sample(_entry: SupervisionTraceEntry) -> None:
            self._max_open_during_child = max(
                self._max_open_during_child, self.counting.open_now
            )

        for sampled in _SAMPLED_KINDS:
            sampler.on(sampled, sample)
        if row.cancel_after_first_heartbeat:

            def cancel_on_heartbeat(entry: SupervisionTraceEntry) -> None:
                if entry.facts.get("event_type") == "HEARTBEAT":
                    cancellation.request_cancellation()

            observer.on(_T.EVENT_ACCEPTED, cancel_on_heartbeat)
        supervisor = build_supervisor(
            lifecycle=self.lifecycle,
            controller=tee,
            clock=self._monotonic,
            supervision_root=str(self.supervision_root),
            supervisor_instance_id=SCRIPTED_SUPERVISOR_INSTANCE_ID,
            cancellation_grace_seconds=1,
            describe_limits=PROTOCOL_LIMITS_DEFAULT,
            preflight=MISSING,
            observers=(observer, sampler),
        )
        self._tees.append(tee)
        self._paths[invocation.invocation_id] = paths
        self._entries[invocation.invocation_id] = entry
        assert self.counting.open_now == 0, "a transaction is open before invoke"
        outcome = ok(asyncio.run(supervisor.invoke(command, cancellation)))
        assert self.counting.open_now == 0, "a transaction survived invoke"
        assert outcome.command_result.invocation.invocation_id == (
            invocation.invocation_id
        )
        return outcome

    def invoke(self, row: Scenario, run: EngineRunRecord) -> SupervisionOutcome:
        """One ``VALIDATE`` or ``RUN`` command through the production supervisor;
        the flow holds no transaction while the child runs."""
        assert row.command is not _K.DESCRIBE
        return self._invoke(row, run)

    def describe(self, row: Scenario) -> DescribeOutcome:
        """S-1: the ``DESCRIBE`` invocation, the bootstrap parse, the describe
        reconciliation (its diagnostics recorded and enriched when any), the
        observation ``AVAIL_A`` minted by ``describe_availability_observation`` and
        persisted through the writer beside the ``ADAPTER``-owned owner row."""
        assert row.command is _K.DESCRIBE
        outcome = self._invoke(row, None)
        invocation = outcome.command_result.invocation
        assert invocation.state is _C.EXITED, invocation.state
        entry = self._entries[invocation.invocation_id]
        paths = self._paths[invocation.invocation_id]
        assert isinstance(paths.output_path, str)
        output_path = Path(paths.output_path)
        parse: Any = MISSING
        if output_path.is_file():
            parse = parse_bootstrap_descriptor(
                output_path.read_bytes(), max_bytes=MAX_DESCRIPTOR_OUTPUT_BYTES
            )
        now = self.clock.now_utc()
        reconciliation = reconcile_describe(
            invocation,
            parse,
            outcome.stdout_byte_count,
            catalog_entry=entry,
            now_utc=now,
        )
        if reconciliation.diagnostics:
            for diagnostic in reconciliation.diagnostics:
                ok(self.recorder.record(diagnostic))
            stored = self.fresh_invocation(invocation.invocation_id)
            ok(
                enrich_invocation(
                    InvocationEnrichmentRequest(
                        schema_version="1.0.0",
                        invocation_id=stored.invocation_id,
                        expected_revision=stored.revision,
                        additional_diagnostic_ids=tuple(
                            sorted(
                                item.diagnostic_id
                                for item in reconciliation.diagnostics
                            )
                        ),
                    ),
                    unit_of_work=self.counting,
                    clock=self.clock,
                )
            )
        primary = reconciliation.primary_diagnostic
        observation = describe_availability_observation(
            adapter_name=entry.adapter_name,
            adapter_version=entry.adapter_version,
            verdict=reconciliation.verdict,
            primary_code=(
                primary.error_code if isinstance(primary, Diagnostic) else MISSING
            ),
            descriptor=reconciliation.descriptor,
            observation_id=AVAIL_A,
            executable_path=entry.executable_path,
            executable_hash=entry.executable_hash,
            runtime_version=FAKE_RUNTIME_VERSION,
            operating_system=FAKE_OPERATING_SYSTEM,
            observed_at_utc=now,
            expires_at_utc=now + OBSERVATION_VALIDITY,
        )
        owner = AdapterArtifactOwner(
            owner_kind="ADAPTER",
            adapter_name=entry.adapter_name,
            adapter_version=entry.adapter_version,
            engine_name=entry.engine.engine_name,
            engine_version=entry.engine.engine_version,
        )
        transaction = self.counting.begin()
        try:
            members = transaction.sqlite()
            ok(members.availability_observation_writer.add(observation))
            owner_hash = ok(members.artifact_owners.register(owner))
            commit(transaction)
        finally:
            transaction.rollback()
        return DescribeOutcome(
            outcome=outcome,
            reconciliation=reconciliation,
            observation=observation,
            owner_hash=owner_hash,
        )

    def conclude(
        self, row: Scenario, run: EngineRunRecord, outcome: SupervisionOutcome
    ) -> SemanticOutcome | None:
        """The epilogue for an ``EXITED`` invocation: the output parsed, the
        candidates observed, ``apply_command_semantic_outcome`` over the counted
        root, then every reconciliation diagnostic recorded (the caller
        obligation of plan 1.4 row 7). A core-won terminal returns ``None``."""
        invocation = outcome.command_result.invocation
        if invocation.state is not _C.EXITED:
            return None
        token = self._token_for(run.run_id)
        paths = self._paths[invocation.invocation_id]
        parse: Any = MISSING
        observations: tuple[CandidateObservation, ...] = ()
        if row.command is _K.VALIDATE:
            assert isinstance(paths.output_path, str)
            output_path = Path(paths.output_path)
            if output_path.is_file():
                parse = parse_validation_result(
                    output_path.read_bytes(),
                    max_bytes=MAX_VALIDATION_RESULT_BYTES,
                    token=token,
                )
        else:
            assert isinstance(paths.work_dir, str)
            assert isinstance(paths.result_path, str)
            work_dir = Path(paths.work_dir)
            result_path = Path(paths.result_path)
            if result_path.is_file():
                parse = parse_result_manifest(
                    result_path.read_bytes(),
                    max_bytes=PROTOCOL_LIMITS_DEFAULT.max_manifest_bytes,
                    token=token,
                )
            observations = _observe_candidates(
                work_dir, outcome.protocol_summary, parse, token
            )
        # B7-03: the stored revisions, re-read after the supervisor's last write.
        stored_run = self.fresh_run(run.run_id)
        stored_invocation = self.fresh_invocation(invocation.invocation_id)
        semantic = ok(
            apply_command_semantic_outcome(
                SemanticOutcomeRequest(
                    schema_version="1.0.0",
                    invocation_id=stored_invocation.invocation_id,
                    expected_invocation_revision=stored_invocation.revision,
                    run_id=stored_run.run_id,
                    expected_run_revision=stored_run.revision,
                    parsed_output=parse,
                    protocol_summary=outcome.protocol_summary,
                    candidate_observations=observations,
                    negotiated_versions=DEFAULT_NEGOTIATED,
                ),
                unit_of_work=self.counting,
                clock=self.clock,
            )
        )
        reconciliation = semantic.reconciliation
        if isinstance(reconciliation, SemanticReconciliation):
            for diagnostic in reconciliation.diagnostics:
                ok(self.recorder.record(diagnostic))
        return semantic

    # -- authoritative post-operation reads ------------------------------------

    def fresh_invocation(self, invocation_id: str) -> CommandInvocationRecord:
        return self._fresh(
            lambda opened: ok(opened.command_invocations.get(invocation_id))
        )

    def fresh_run(self, run_id: str) -> EngineRunRecord:
        return self._fresh(lambda opened: ok(opened.engine_runs.get(run_id)))

    def fresh_events(self, invocation_id: str) -> tuple[RunEvent, ...]:
        return self._fresh(
            lambda opened: ok(opened.engine_runs.list_events(invocation_id))
        )

    def fresh_diagnostic(self, diagnostic_id: object) -> Diagnostic:
        """The stored diagnostic behind a record's primary reference, which must
        be present (a ``MISSING`` reference fails here, never resolves)."""
        assert isinstance(diagnostic_id, str), "the record names no primary"
        return self._fresh(lambda opened: ok(opened.diagnostics.get(diagnostic_id)))

    def fresh_observation(self, observation_id: str) -> RuntimeAvailabilityObservation:
        return self._fresh(
            lambda opened: ok(opened.availability_observations.get(observation_id))
        )

    def fresh_owner(self, owner_hash: str) -> ArtifactOwnerRef:
        return self._fresh(lambda opened: ok(opened.artifact_owners.get(owner_hash)))

    def fresh_experiment(self, experiment_id: str) -> ExperimentRecord:
        return self._fresh(lambda opened: ok(opened.experiments.get(experiment_id)))

    def frozen_snapshot(self, experiment_id: str) -> ConfigSnapshot:
        snapshot = self._fresh(
            lambda opened: ok(opened.configuration_snapshots.get(experiment_id))
        )
        assert isinstance(snapshot, ConfigSnapshot), "no snapshot is frozen"
        return snapshot

    def consistency_report(self) -> ConsistencyReport:
        return self.database.consistency_report()

    def run_states(self) -> frozenset[EngineRunState]:
        return run_states_of(self.database)

    def independent_counts(self, invocation_id: str) -> tuple[int, int]:
        """The memory-bound control: the invocation's row count and its event row
        count through an independent stdlib connection on the same file."""
        connection = raw_connection(self.database.path)
        try:
            invocations = connection.execute(
                _INVOCATION_COUNT_SQL, (invocation_id,)
            ).fetchone()
            events = connection.execute(_EVENT_COUNT_SQL, (invocation_id,)).fetchone()
        finally:
            connection.close()
        assert invocations is not None
        assert events is not None
        return int(invocations[0]), int(events[0])

    def token_absent_everywhere(self, run_id: str) -> bool:
        """A full-text scan of every user table for the raw token the flow held
        for ``run_id``: every ``TEXT`` cell and every JSON snapshot, read through
        the independent connection. ``True`` when no cell carries it."""
        token = self._token_for(run_id)
        encoded = token.encode("utf-8")
        connection = raw_connection(self.database.path)
        try:
            tables = [str(row[0]) for row in connection.execute(_USER_TABLES_SQL)]
            for table in tables:
                assert table.replace("_", "").isalnum(), table
                # The identifier comes from sqlite_master and was just checked;
                # SQLite admits no bound parameter in place of a table name.
                for row in connection.execute(f'SELECT * FROM "{table}"'):  # noqa: S608
                    for cell in row:
                        if isinstance(cell, str) and token in cell:
                            return False
                        if isinstance(cell, bytes) and encoded in cell:
                            return False
        finally:
            connection.close()
        return True

    def database_sha256(self) -> str:
        """The SHA-256 of the checkpointed main file (ledger A7-01/B7-01).

        Under WAL the committed rows live in the ``-wal`` sidecar until a
        checkpoint, so the main file alone would not change. The flow asserts
        quiescence first -- no counted transaction open, no pooled connection
        checked out -- then runs ``PRAGMA wal_checkpoint(TRUNCATE)`` through the
        independent connection and checks its result: not busy, every frame
        checkpointed, the sidecar truncated to zero bytes. Only then is the main
        file hashed, under the same conditions before and after a row.
        """
        assert self.counting.open_now == 0, "a counted transaction is open"
        pool = engine_of(self.database).pool
        assert isinstance(pool, QueuePool)
        assert pool.checkedout() == 0, "a pooled connection is checked out"
        path = self.database.path
        connection = raw_connection(path)
        try:
            row = connection.execute(_CHECKPOINT_SQL).fetchone()
        finally:
            connection.close()
        assert row is not None
        busy, frames, checkpointed = (int(value) for value in row)
        assert busy == 0, "the checkpoint found a busy reader or writer"
        assert frames == checkpointed, "frames remained in the write-ahead log"
        sidecar = Path(f"{path}-wal")
        assert not sidecar.exists() or sidecar.stat().st_size == 0
        return file_sha256(path)

    def quick_check(self) -> str:
        connection = raw_connection(self.database.path)
        try:
            row = connection.execute(_QUICK_CHECK_SQL).fetchone()
        finally:
            connection.close()
        assert row is not None
        return str(row[0])

    def reconcile(self) -> ReconciliationReport:
        """S-8: one reconciliation pass over ``SqliteReconciliationSource`` with a
        fresh lifecycle, recorder and controller over this (reopened) database."""
        preflight = PathPreflight(
            supervision_root=str(self.supervision_root),
            long_paths_supported=False,
            directory_ceiling=_DIRECTORY_CEILING,
            file_ceiling=_FILE_CEILING,
            probed_at_utc=INSTANT,
        )
        return ok(
            reconcile_invocations(
                source=SqliteReconciliationSource(self.database, self.clock),
                lifecycle=Stage5InvocationLifecycle(
                    unit_of_work=SqliteUnitOfWork(self.database, self.clock),
                    clock=self.clock,
                    diagnostics=SqliteDiagnosticRecorder(
                        self.database, clock=self.clock
                    ),
                ),
                controller=WindowsProcessController(),
                preflight=preflight,
                clock=self.clock,
                supervisor_instance_id=SCRIPTED_SUPERVISOR_INSTANCE_ID,
                observer=MISSING,
            )
        )

    # -- hygiene --------------------------------------------------------------

    def _assert_nothing_launched_survives(self) -> None:
        """Every identity a tee launched or recorded as a descendant is terminated
        if still ours and asserted not ``ALIVE_MATCHING`` through a fresh controller."""
        fresh = WindowsProcessController()
        for tee in self._tees:
            recorded = [*tee.identities] + [
                (item.pid, item.creation_identity) for item in tee.descendants
            ]
            for pid, creation_identity in recorded:
                identity = ProcessIdentity(
                    pid=pid,
                    creation_identity=creation_identity,
                    executable_path=self._launcher_path,
                    executable_hash=self._launcher_hash,
                    supervisor_instance_id=SCRIPTED_SUPERVISOR_INSTANCE_ID,
                )
                if fresh.inspect(identity).presence is ProcessPresence.ALIVE_MATCHING:
                    fresh.terminate_tree(identity, FORCED_TERMINATION_EXIT_CODE)
                assert fresh.inspect(identity).presence is not (
                    ProcessPresence.ALIVE_MATCHING
                )
