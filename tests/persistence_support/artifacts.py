"""SQLite test support for the Stage 9 artifact persistence suites (plan 7.1,
Task 5).

``ArtifactHarness(database)`` is ``PortHarness``-style over ``SqliteUnitOfWork``:
it wraps the Stage 8 ``SqliteHarness`` so every unit of work it hands out is
tracked and rolled back at ``close()``, seeds the RESULT pre-state the Stage 9
rows reference (``seed_result_prestate``: the experiment, the availability
observation, a ``RUNNING`` run with its deadline snapshotted through
``snapshot_deadline``, the ``EXITED`` run-command invocation and the owner rows
of plan 3.3), writes committed candidates, references, journal entries and
registration facts through the production repositories (``put_candidate``,
``put_ref``, ``put_journal``, ``put_sanitized_manifest``, ``put_run_manifest``,
``put_validation_result``, ``put_run_artifact``), reads committed state back
through a fresh read-only session decoded by the production codecs
(``committed_candidates``, ``committed_refs``, ``committed_manifests``,
``committed_journal``, ``committed_audit_events``, ``committed_run_manifests``,
``committed_run_artifacts``), and offers the raw-statement side the trigger
refusal tests need: ``plant_raw(table, row)`` inserts one row through the
independent stdlib connection after checking the table and columns against the
metadata, ``refuse(statement, parameters)`` executes one statement through the
engine and returns its classified refusal (failing the test when the statement
is accepted), ``execute(statement, parameters)`` commits a positive control, and
``install_refusing_trigger(table, when)`` / ``install_ignoring_update_trigger``
install test-only triggers from fixed DDL text plus one checked identity literal
(the Stage 8 ``sql_identity_literal`` rule: SQLite admits no bound parameter
inside ``CREATE TRIGGER``).

``token_scan(path_or_bytes, token)`` is the test-side exact-byte scan --
``bytes.find`` over the whole file, an implementation independent of the
production scanner it cross-checks -- and ``scan_tree_for_token(root, token)``
applies it to every file under ``root``.

Task 7 (plan 7.1, 4.4): ``FinalizationFixture.open(..., production=True)``
composes the production ``ResultRegistrar``, ``ResultRecoveryValidator`` and
``AuditFactRecorder`` instead of the Task 6 doubles, and its RESULT pre-state
(``plant_production_result``) is the real adapter wire: an
``AdapterResultManifest`` carrying the fixture token and the declarations of the
planted files, the ``ARTIFACT_PRODUCED``/``FINAL_RESULT`` ledger appended
through ``engine_runs.append_event``, the sanitized row the Stage 6 conclusion
would have written, and a request whose hashes derive from those bytes -- so a
RESULT finalization can reach ``REGISTERED`` success here.

Nothing here imports ``subprocess``, launches a child or reads a clock of its
own; every failure is stamped from the shared ``FixedClock(INSTANT)``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Final

import pytest
from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING
from sqlalchemy import Select, select
from sqlalchemy.exc import DBAPIError

from contract.harness import DEFAULT_NEGOTIATED
from contract.scenarios import SCENARIOS, Scenario
from crypto_lab.adapters.envelopes import (
    AdapterCommandRequestEnvelope,
    EngineRunRequest,
    NegotiatedVersions,
)
from crypto_lab.adapters.events import (
    ArtifactProducedPayload,
    FinalResultPayload,
    InvocationEventLedger,
    ProtocolEventSummary,
    RunEvent,
    run_event_content_hash,
)
from crypto_lab.adapters.limits import (
    MAX_RESULT_MANIFEST_BYTES,
    RESULT_MANIFEST_RELATIVE_PATH,
)
from crypto_lab.adapters.manifests import (
    AdapterResultManifest,
    ManifestParse,
    RunProvenance,
    SanitizedAdapterResultManifest,
    parse_result_manifest,
    sanitize_result_manifest,
)
from crypto_lab.adapters.negotiation import DescriptorParse
from crypto_lab.adapters.reconciliation import CandidateObservation
from crypto_lab.adapters.sanitization import StderrCapture
from crypto_lab.adapters.vocabulary import (
    NEGOTIABLE_SCHEMA_NAMES,
    ProtocolEventType,
    SemanticStatus,
)
from crypto_lab.artifacts.finalizer import CoreArtifactFinalizer
from crypto_lab.artifacts.hashing import StreamingContentHasher
from crypto_lab.artifacts.journal import (
    FinalizationJournalEntry,
    FinalizationJournalState,
)
from crypto_lab.artifacts.manifest import ArtifactManifest
from crypto_lab.artifacts.models import (
    ArtifactRef,
    CandidateArtifact,
    CandidateArtifactState,
    FinalizationResult,
)
from crypto_lab.artifacts.ownership import ArtifactOwnerRef, RunArtifactOwner
from crypto_lab.artifacts.ports import (
    CommandRootPaths,
    FinalizationAuditor,
    FinalizationLog,
    FinalizationProbe,
    LogFact,
    NoProbe,
    PurposeRegistrar,
)
from crypto_lab.artifacts.ports import (
    ResultRecoveryValidator as ResultRecoveryValidatorPort,
)
from crypto_lab.artifacts.recovery import (
    FinalizationReconciliationReport,
    reconcile_finalization,
)
from crypto_lab.artifacts.requests import (
    EvidenceCorrelation,
    EvidenceFinalizationRequest,
    ResultFinalizationRequest,
)
from crypto_lab.artifacts.store import ArtifactStore, QuarantineEntry
from crypto_lab.audit.jsonl import JsonLinesLogWriter, log_write_failure
from crypto_lab.audit.models import AuditEvent, LogRecord, LogSeverity
from crypto_lab.audit.redaction import REDACTED, contains_token_shape, redact_details
from crypto_lab.configuration.models import ApplicationConfig, ProcessConfig
from crypto_lab.configuration.snapshot import ConfigSnapshot
from crypto_lab.datasets.models import DatasetDescriptor, DatasetPartition
from crypto_lab.domain.base import SCHEMA_VERSION
from crypto_lab.domain.canonical_json import canonical_json_bytes, canonical_json_text
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.descriptors import SupportedSchemaVersion
from crypto_lab.domain.diagnostics import Diagnostic, DiagnosticCategory
from crypto_lab.domain.engine_run import AttemptTokenMaterial, EngineRunRecord
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.hashing import (
    CanonicalHashEnvelope,
    HashingProfile,
    _uuid4_shaped,
    run_manifest_id_for,
    sha256_bytes,
)
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
    ProcessExitCategory,
)
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result
from crypto_lab.experiments.experiment_service import cancel_experiment
from crypto_lab.experiments.finalization import (
    AuditFactRecorder,
    CommandConclusion,
    ConclusionConfig,
    ResultRegistrar,
    conclude_command,
    conclude_describe,
    declared_candidate_paths,
    fail_run_for_refusal,
    finalize_evidence,
    observe_candidates,
    protocol_capture_evidence,
    semantic_outcome_or_replay,
    stderr_evidence,
)
from crypto_lab.experiments.finalization import (
    ResultRecoveryValidator as ProductionRecoveryValidator,
)
from crypto_lab.experiments.requests import (
    CancelExperimentRequest,
    RunTransitionRequest,
    SemanticOutcomeRequest,
)
from crypto_lab.experiments.run_manifest import (
    NormalizedResultProvenance,
    RunManifest,
    run_manifest_hash,
)
from crypto_lab.experiments.run_service import transition_run
from crypto_lab.persistence.artifact_codecs import (
    decode_artifact_manifest,
    decode_artifact_ref,
    decode_audit_event,
    decode_candidate_artifact,
    decode_finalization_journal_entry,
    encode_artifact_ref,
    encode_finalization_journal_entry,
)
from crypto_lab.persistence.artifact_repositories import (
    RunArtifactLink,
    RunManifestFacts,
    SanitizedManifestFacts,
    ValidationResultFacts,
)
from crypto_lab.persistence.codecs import decode_diagnostic, micros_to_utc_text
from crypto_lab.persistence.database import SqliteDatabase
from crypto_lab.persistence.registries import (
    SqliteArtifactOwnerRegistry,
    SqliteDiagnosticRecorder,
)
from crypto_lab.persistence.schema import (
    STAGE8_TABLE_COUNT,
    TABLES_IN_DEPENDENCY_ORDER,
    ArtifactRefRow,
    AuditEventRow,
    CandidateArtifactRow,
    DiagnosticRow,
    FinalizationJournalRow,
    RunArtifactRow,
    RunManifestRow,
    metadata,
)
from crypto_lab.persistence.unit_of_work import SqliteTransaction, SqliteUnitOfWork
from crypto_lab.process_supervision.models import (
    ReconciliationReport,
    SupervisionOutcome,
    SupervisionTraceEntry,
)
from crypto_lab.process_supervision.roots import CommandPaths
from crypto_lab.strategy.versioning import StrategyVersion, strategy_version_payload
from doubles.artifacts import (
    ADAPTER_MANIFEST_ID,
    ADAPTER_OWNER,
    ATTEMPT_TOKEN_HASH,
    CANDIDATE_ID,
    DEADLINE,
    EVIDENCE_FILES,
    FIXTURE_TOKEN,
    INVOCATION_CORRELATION,
    NATIVE_KIND,
    NATIVE_MEDIA,
    OTHER_CANDIDATE_ID,
    RESULT_FILES,
    RESULT_TIMEOUT_SECONDS,
    RUN_OWNER,
    RUN_OWNER_WITHOUT_INVOCATION,
    SANITIZED_MANIFEST_HASH,
    SYSTEM_OWNER,
    ArtifactStoreFixture,
    DurableState,
    EvidencePlan,
    FactAuditor,
    FlagCancellationToken,
    MemoryRecoveryValidator,
    MemoryRegistrar,
    RecordingLog,
    RecordingProbe,
    ResultPlan,
    SequentialAuditIds,
    plant_command_root,
    plant_core_evidence,
    read_token_material,
    result_candidates,
    run_coroutine,
    sample_candidate,
    sample_evidence_request,
    sample_metric,
    sample_ref,
    sample_result_request,
)
from doubles.experiments import (
    ADAPTER_ALPHA,
    ARTIFACT_ID,
    DATASET_HASH,
    DIAG_ID,
    ENGINE_ALPHA,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    OTHER_DIAG_ID,
    REQUEST_HASH,
    RUN_ID,
    SLOT_A,
    STRATEGY_HASH,
    FixedClock,
    sample_diagnostic,
    sample_experiment,
    sample_invocation,
    sample_run,
)
from persistence_support.harness import (
    SqliteHarness,
    commit,
    ok,
    open_test_database,
    put_experiment,
    put_invocation,
    put_lifecycle_parents,
    put_run,
    raw_connection,
    sql_identity_literal,
)
from persistence_support.supervised import DescribeOutcome, SupervisedSqliteFlow

__all__ = [
    "DEFAULT_NEGOTIATED_VERSIONS",
    "FINALIZATION_TIMEOUT_SECONDS",
    "FINALIZING_CONFIG",
    "RUNNING_EXPERIMENT",
    "STAGE9_SUPERVISED_ROW_NAMES",
    "STAGE9_TABLES",
    "TRIGGER_TABLES",
    "ArtifactHarness",
    "ClockAdvancingProbe",
    "DescribeConclusion",
    "FinalizationFixture",
    "FinalizingSupervisedFlow",
    "JsonLinesFinalizationLog",
    "ProductionResultPlan",
    "RecoveryReports",
    "Refusal",
    "ResultPrestate",
    "TokenScanReport",
    "configuration_audit_bytes",
    "dataset_identity_bytes",
    "sample_normalized_provenance",
    "sample_run_manifest",
    "sample_run_provenance",
    "scan_tree_for_token",
    "strategy_identity_bytes",
    "token_scan",
]

#: Plan 3.3: the eight Stage 9 tables, in dependency order.
STAGE9_TABLES: Final[tuple[str, ...]] = TABLES_IN_DEPENDENCY_ORDER[STAGE8_TABLE_COUNT:]
#: The tables a test-only trigger may be installed on: the Stage 9 tables and the
#: two Stage 8 tables Stage 9 triggers touch.
TRIGGER_TABLES: Final[frozenset[str]] = frozenset(
    {*STAGE9_TABLES, "engine_runs", "command_invocations"}
)
_TRIGGER_EVENTS: Final[frozenset[str]] = frozenset({"INSERT", "UPDATE"})
#: ``NEW.<column> = '<identity>'``: the only ``WHEN`` shape an installer admits.
_WHEN_GRAMMAR: Final = re.compile(r"^NEW\.([a-z_]+) = ('[a-z]+_[0-9a-f-]{36}')$")
#: The owner rows the default pre-state registers, in registration order.
DEFAULT_OWNERS: Final[tuple[ArtifactOwnerRef, ...]] = (
    RUN_OWNER,
    RUN_OWNER_WITHOUT_INVOCATION,
    SYSTEM_OWNER,
    ADAPTER_OWNER,
)


@dataclass(frozen=True, slots=True)
class Refusal:
    """One refused raw statement: the classified code and the driver's message."""

    code: str
    message: str


@dataclass(frozen=True, slots=True)
class ResultPrestate:
    """The rows ``seed_result_prestate`` committed, as the records it wrote; the
    owner hashes are parallel to the ``owners`` it registered."""

    run: EngineRunRecord
    invocation: CommandInvocationRecord
    owners: tuple[ArtifactOwnerRef, ...]
    owner_hashes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProductionResultPlan(ResultPlan):
    """The Task 7 RESULT pre-state beside the planted rows and request: the
    adapter manifest bytes as written under the work directory, the appended
    ledger, the parse and summary the Stage 6 flow would hand the verdict, and
    the sanitized manifest the request's hashes derive from."""

    manifest_bytes: bytes
    events: tuple[RunEvent, ...]
    parse: ManifestParse
    summary: ProtocolEventSummary
    sanitized: SanitizedAdapterResultManifest


def _instant(value: object) -> datetime:
    return datetime.fromisoformat(micros_to_utc_text(int(str(value))))


def _optional_text(value: object) -> Any:
    return value if isinstance(value, str) else MISSING


def token_scan(path_or_bytes: Path | bytes, token: str | bytes) -> bool:
    """Does the file (or the bytes) contain ``token`` exactly? ``bytes.find`` over
    the whole content, independent of the production scanner."""
    if isinstance(path_or_bytes, Path):
        data = path_or_bytes.read_bytes()
    else:
        data = path_or_bytes
    needle = token.encode("utf-8") if isinstance(token, str) else token
    if not needle:
        raise ValueError("token must not be empty")
    return data.find(needle) != -1


def scan_tree_for_token(root: Path, token: str | bytes) -> tuple[Path, ...]:
    """Every regular file under ``root`` whose bytes contain ``token``, sorted."""
    return tuple(
        path
        for path in sorted(root.rglob("*"))
        if path.is_file() and token_scan(path, token)
    )


class ArtifactHarness:
    """``PortHarness``-style support over one migrated SQLite database (plan 7.1)."""

    __slots__ = ("_clock", "_inner", "database")

    def __init__(self, database: SqliteDatabase) -> None:
        self.database = database
        self._inner = SqliteHarness(database)
        self._clock = FixedClock(INSTANT)

    # -- Units of work -------------------------------------------------------

    def unit_of_work(self) -> SqliteUnitOfWork:
        """A fresh root over the same database, tracked for teardown."""
        return self._inner.unit_of_work()

    def begin(self) -> SqliteTransaction:
        """One open transaction over a fresh root."""
        return self.unit_of_work().begin()

    def lifecycle(self) -> SqliteHarness:
        """The Stage 8 harness underneath, for the lifecycle helpers."""
        return self._inner

    def open_transactions(self) -> tuple[SqliteTransaction, ...]:
        return self._inner.open_transactions()

    def close(self) -> None:
        """Roll back every surviving transaction, then dispose the engine."""
        self._inner.close()

    # -- Pre-state ------------------------------------------------------------

    def seed_result_prestate(
        self,
        *,
        run_state: EngineRunState = EngineRunState.RUNNING,
        deadline: datetime | None = DEADLINE,
        invocation_state: CommandInvocationState = CommandInvocationState.EXITED,
        owners: tuple[ArtifactOwnerRef, ...] = DEFAULT_OWNERS,
    ) -> ResultPrestate:
        """The parents every Stage 9 row references: the experiment and
        observation, the run in ``run_state`` (its deadline snapshotted when
        ``RUNNING`` and ``deadline`` is given), the run-command invocation in
        ``invocation_state`` and the owner rows."""
        put_lifecycle_parents(self._inner, observation=True)
        run = sample_run(run_state)
        put_run(self._inner, run)
        if deadline is not None and run_state is EngineRunState.RUNNING:
            transaction = self.begin()
            run = ok(
                transaction.result_leases.snapshot_deadline(
                    run.revision, RUN_ID, deadline
                )
            )
            commit(transaction)
        invocation = sample_invocation(invocation_state, kind=CommandKind.RUN)
        put_invocation(self._inner, invocation)
        hashes = tuple(self.put_owner(owner) for owner in owners)
        return ResultPrestate(
            run=run, invocation=invocation, owners=owners, owner_hashes=hashes
        )

    def put_owner(self, owner: ArtifactOwnerRef) -> str:
        """Register one owner row in its own committed transaction."""
        transaction = self.begin()
        owner_hash = ok(transaction.artifact_owners.register(owner))
        commit(transaction)
        return owner_hash

    # -- Committed writers ----------------------------------------------------

    def put_candidate(self, record: CandidateArtifact) -> None:
        transaction = self.begin()
        ok(transaction.candidate_artifacts.add(record))
        commit(transaction)

    def put_ref(self, ref: ArtifactRef, manifest: ArtifactManifest) -> None:
        """Plant one reference row raw (its candidate must be ``FINALIZING``)."""
        self.plant_raw("artifact_refs", encode_artifact_ref(ref, manifest))

    def put_journal(self, entry: FinalizationJournalEntry) -> None:
        """``prepare`` a ``PREPARED`` entry; plant any other state raw."""
        if entry.state is FinalizationJournalState.PREPARED:
            transaction = self.begin()
            ok(transaction.finalization_journal.prepare(entry))
            commit(transaction)
            return
        row = encode_finalization_journal_entry(entry)
        self.plant_raw("finalization_journal", row)

    def put_sanitized_manifest(self, facts: SanitizedManifestFacts) -> None:
        transaction = self.begin()
        ok(transaction.sanitized_manifests.add(facts))
        commit(transaction)

    def put_run_manifest(self, facts: RunManifestFacts) -> None:
        transaction = self.begin()
        ok(transaction.run_manifests.add(facts))
        commit(transaction)

    def put_validation_result(self, facts: ValidationResultFacts) -> None:
        transaction = self.begin()
        ok(transaction.validation_results.add(facts))
        commit(transaction)

    def put_run_artifact(self, link: RunArtifactLink) -> None:
        transaction = self.begin()
        ok(transaction.run_artifacts.link(link))
        commit(transaction)

    # -- Committed readers (a fresh read-only session each) -------------------

    def committed_candidates(self) -> tuple[CandidateArtifact, ...]:
        statement = select(CandidateArtifactRow).order_by(
            CandidateArtifactRow.candidate_artifact_id
        )
        return tuple(
            ok(decode_candidate_artifact(row, owner=owner, clock=self._clock))
            for row, owner in self._owned_rows(statement)
        )

    def committed_refs(self) -> tuple[ArtifactRef, ...]:
        statement = select(ArtifactRefRow).order_by(ArtifactRefRow.artifact_id)
        return tuple(
            ok(decode_artifact_ref(row, owner=owner, clock=self._clock))
            for row, owner in self._owned_rows(statement)
        )

    def committed_manifests(self) -> tuple[ArtifactManifest, ...]:
        statement = select(ArtifactRefRow).order_by(ArtifactRefRow.artifact_id)
        return tuple(
            ok(decode_artifact_manifest(row, clock=self._clock))
            for row in self._rows(statement)
        )

    def committed_journal(self) -> tuple[FinalizationJournalEntry, ...]:
        statement = select(FinalizationJournalRow).order_by(
            FinalizationJournalRow.finalization_id
        )
        return tuple(
            ok(decode_finalization_journal_entry(row, owner=owner, clock=self._clock))
            for row, owner in self._owned_rows(statement)
        )

    def committed_audit_events(self) -> tuple[AuditEvent, ...]:
        statement = select(AuditEventRow).order_by(AuditEventRow.audit_sequence)
        return tuple(
            ok(decode_audit_event(row, clock=self._clock))
            for row in self._rows(statement)
        )

    def committed_run_manifests(self) -> tuple[RunManifestFacts, ...]:
        statement = select(RunManifestRow).order_by(RunManifestRow.manifest_id)
        return tuple(
            RunManifestFacts(
                manifest_id=str(row["manifest_id"]),
                run_id=str(row["run_id"]),
                experiment_id=str(row["experiment_id"]),
                run_invocation_id=str(row["run_invocation_id"]),
                attempt_token_hash=str(row["attempt_token_hash"]),
                sanitized_adapter_result_manifest_hash=str(
                    row["sanitized_adapter_result_manifest_hash"]
                ),
                semantic_status=str(row["semantic_status"]),
                process_exit_category=str(row["process_exit_category"]),
                manifest_json=str(row["manifest_json"]),
                run_manifest_hash=str(row["run_manifest_hash"]),
                registered_at_utc=_instant(row["registered_at_utc"]),
            )
            for row in self._rows(statement)
        )

    def committed_run_artifacts(self) -> tuple[RunArtifactLink, ...]:
        statement = select(RunArtifactRow).order_by(
            RunArtifactRow.run_id,
            RunArtifactRow.link_role,
            RunArtifactRow.artifact_id,
        )
        return tuple(
            RunArtifactLink(
                run_id=str(row["run_id"]),
                artifact_id=str(row["artifact_id"]),
                link_role=str(row["link_role"]),
                experiment_id=str(row["experiment_id"]),
                run_manifest_id=_optional_text(row["run_manifest_id"]),
            )
            for row in self._rows(statement)
        )

    def count(self, table: str) -> int:
        """``SELECT count(*)`` of one table through the stdlib connection."""
        _require_table(table)
        connection = raw_connection(self.database.path)
        try:
            statement = f"SELECT count(*) FROM {table}"  # noqa: S608
            (total,) = connection.execute(statement).fetchone()
            return int(total)
        finally:
            connection.close()

    # -- Raw statements -------------------------------------------------------

    def plant_raw(self, table: str, row: Mapping[str, object]) -> None:
        """Insert one row through the independent stdlib connection.

        ``table`` must be a metadata table and every key a column of it; the
        statement text is composed from those checked names alone and every
        value is a bound parameter.
        """
        statement, parameters = _insert_statement(table, row)
        connection = raw_connection(self.database.path)
        try:
            connection.execute(statement, parameters)
        finally:
            connection.close()

    def refuse_insert(self, table: str, row: Mapping[str, object]) -> Refusal:
        """``refuse`` over the insert of ``row``, composed as ``plant_raw`` does."""
        statement, parameters = _insert_statement(table, row)
        return self.refuse(statement, parameters)

    def refuse(self, statement: str, parameters: tuple[object, ...] = ()) -> Refusal:
        """Execute one statement through the engine and return its classified
        refusal; a statement the database accepts fails the test."""
        with self.database.connection() as connection:
            try:
                connection.exec_driver_sql(statement, parameters)
            except DBAPIError as error:
                connection.rollback()
                return Refusal(
                    code=SqliteDatabase.classify(error), message=str(error.orig)
                )
            connection.rollback()
        pytest.fail(f"the database accepted a statement it must refuse: {statement}")

    def execute(self, statement: str, parameters: tuple[object, ...] = ()) -> None:
        """Execute and commit one positive-control statement through the engine."""
        with self.database.connection() as connection:
            connection.exec_driver_sql(statement, parameters)
            connection.commit()

    def install_refusing_trigger(
        self, table: str, when: str, *, event: str = "INSERT"
    ) -> None:
        """A test-only ``BEFORE <event>`` trigger refusing the row ``when`` names.

        ``when`` is ``NEW.<column> = '<identity>'`` over one fixture identity
        (the ``sql_identity_literal`` grammar); nothing else is admitted into the
        DDL text.
        """
        verb = _require_event(event).lower()
        _execute_ddl(
            self.database,
            f"CREATE TRIGGER test_refuse_{table}_{verb} "
            f"BEFORE {_require_event(event)} ON {_require_trigger_table(table)} "
            f"WHEN {_require_when(when)} "
            f"BEGIN SELECT RAISE(ABORT, 'test: {table} {verb} refused'); END",
        )

    def install_ignoring_update_trigger(self, table: str, when: str) -> None:
        """A test-only ``BEFORE UPDATE`` trigger skipping the row ``when`` names
        (``RAISE(IGNORE)``), the one way a conditional ``UPDATE`` reports zero rows
        from inside one connection (Stage 8 plan 4.3.1 step f)."""
        _execute_ddl(
            self.database,
            f"CREATE TRIGGER test_ignore_{table}_update "
            f"BEFORE UPDATE ON {_require_trigger_table(table)} "
            f"WHEN {_require_when(when)} BEGIN SELECT RAISE(IGNORE); END",
        )

    # -- Internals -------------------------------------------------------------

    def _rows(self, statement: Select[Any]) -> tuple[dict[str, object], ...]:
        with self.database.read_only() as connection:
            return tuple(
                {str(key): value for key, value in row.items()}
                for row in connection.execute(statement).mappings().all()
            )

    def _owned_rows(
        self, statement: Select[Any]
    ) -> tuple[tuple[dict[str, object], ArtifactOwnerRef], ...]:
        with self.database.read_only() as connection:
            registry = SqliteArtifactOwnerRegistry(connection, clock=self._clock)
            rows = connection.execute(statement).mappings().all()
            return tuple(
                (
                    {str(key): value for key, value in row.items()},
                    ok(registry.get(str(row["owner_hash"]))),
                )
                for row in rows
            )


def _require_table(table: str) -> str:
    if table not in TABLES_IN_DEPENDENCY_ORDER:
        raise ValueError(f"{table} is not a metadata table")
    return table


def _insert_statement(
    table: str, row: Mapping[str, object]
) -> tuple[str, tuple[object, ...]]:
    """The parameterized insert of ``row`` into the checked ``table``: the text
    is composed from metadata column names alone, every value is bound."""
    _require_table(table)
    columns = tuple(row)
    unknown = set(columns) - set(metadata.tables[table].columns.keys())
    if unknown:
        raise ValueError(f"{table} has no column {sorted(unknown)}")
    names = ", ".join(columns)
    placeholders = ", ".join("?" for _ in columns)
    statement = f"INSERT INTO {table} ({names}) VALUES ({placeholders})"  # noqa: S608
    return statement, tuple(row[column] for column in columns)


def _require_trigger_table(table: str) -> str:
    if table not in TRIGGER_TABLES:
        raise ValueError(f"{table} admits no test-only trigger")
    return table


def _require_event(event: str) -> str:
    if event not in _TRIGGER_EVENTS:
        raise ValueError(f"{event} is not a test-only trigger event")
    return event


def _require_when(when: str) -> str:
    matched = _WHEN_GRAMMAR.match(when)
    if matched is None:
        raise ValueError("when must be NEW.<column> = '<fixture identity>'")
    literal = matched.group(2)
    if sql_identity_literal(literal[1:-1]) != literal:
        raise ValueError("when must name a fixture identity")
    return when


def _execute_ddl(database: SqliteDatabase, statement: str) -> None:
    connection = raw_connection(database.path)
    try:
        connection.execute(statement)
    finally:
        connection.close()


# --------------------------------------------------------------------------
# Task 7 (plan 7.1): the run-manifest builders over the doubles' identities
# --------------------------------------------------------------------------

#: The token-free negotiated versions the Stage 8 flow pins for every request
#: (``tests/persistence_support/supervised.py``); the manifest provenance of a
#: Task 7 pre-state restates them.
DEFAULT_NEGOTIATED_VERSIONS: Final = NegotiatedVersions(
    protocol_version="1.0.0",
    schema_versions=tuple(
        SupportedSchemaVersion(schema_name=name, schema_version=SCHEMA_VERSION)
        for name in NEGOTIABLE_SCHEMA_NAMES
    ),
    capability_vocabulary_version="capabilities/v1",
)
#: The ``RUNNING`` experiment every RESULT pre-state plants (``plant_run``); its
#: spec hash and configuration hash are the provenance facts the manifest echoes.
RUNNING_EXPERIMENT: Final = sample_experiment(ExperimentState.RUNNING)
_SUCCESS_STATUSES: Final = ("SUCCEEDED", "SUCCEEDED_WITH_WARNINGS")


def _without_missing(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if value is not MISSING}


def sample_run_provenance(**overrides: Any) -> RunProvenance:
    """The provenance ``sample_run`` and ``RUNNING_EXPERIMENT`` reconcile against
    (plan 9.2 check 5 of Stage 6): every value is one the request handed the
    adapter."""
    payload: dict[str, Any] = {
        "experiment_spec_hash": RUNNING_EXPERIMENT.spec_hash,
        "request_hash": REQUEST_HASH,
        "strategy_version_hash": STRATEGY_HASH,
        "dataset_version_hash": DATASET_HASH,
        "configuration_hash": RUNNING_EXPERIMENT.spec.configuration_hash,
        "adapter": ADAPTER_ALPHA,
        "engine": ENGINE_ALPHA,
        "negotiated_versions": DEFAULT_NEGOTIATED_VERSIONS,
        "comparison_level": ComparisonLevel.LEVEL_2,
        "logical_slot_id": SLOT_A,
        "attempt_number": 1,
    }
    payload.update(overrides)
    return RunProvenance.model_validate(_without_missing(payload))


def sample_run_manifest(
    refs: tuple[ArtifactRef, ...] | None = None, **overrides: Any
) -> RunManifest:
    """A core run manifest over the doubles' run, its run-command invocation and
    two ``RUN``-owned ``RESULT`` references, its self-hash recomputed; an override
    whose value is ``MISSING`` removes the key."""
    if refs is None:
        refs = tuple(
            sample_ref(
                sample_candidate(
                    state=CandidateArtifactState.FINALIZING,
                    candidate_artifact_id=candidate_id,
                )
            )
            for candidate_id in (OTHER_CANDIDATE_ID, CANDIDATE_ID)
        )
    # A non-reference payload (a planted candidate) keeps its place: the model,
    # not the builder, is what refuses it.
    refs = tuple(sorted(refs, key=lambda ref: str(getattr(ref, "artifact_id", ""))))
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "protocol_version": "1.0.0",
        "manifest_id": run_manifest_id_for(RUN_ID, INVOCATION_ID),
        "experiment_id": EXPERIMENT_ID,
        "run_id": RUN_ID,
        "run_invocation_id": INVOCATION_ID,
        "attempt_token_hash": ATTEMPT_TOKEN_HASH,
        "sanitized_adapter_result_manifest_hash": SANITIZED_MANIFEST_HASH,
        "semantic_status": "SUCCEEDED",
        "process_exit_category": ProcessExitCategory.SUCCESS,
        "started_at_utc": INSTANT,
        "completed_at_utc": INSTANT + timedelta(minutes=5),
        "provenance": sample_run_provenance(),
        "artifact_refs": refs,
        "metrics": (
            (sample_metric(source_artifact_id=refs[0].artifact_id),)
            if refs and isinstance(refs[0], ArtifactRef)
            else ()
        ),
        "diagnostics": (),
        "warnings": (),
        "approximations": (),
    }
    payload.update(overrides)
    payload = _without_missing(payload)
    if "run_manifest_hash" not in payload:
        try:
            draft = RunManifest.model_construct(**payload, run_manifest_hash="0" * 64)
            payload["run_manifest_hash"] = run_manifest_hash(draft)
        except (AttributeError, TypeError, ValueError):
            # A deliberately malformed payload has no recomputable hash; the
            # placeholder lets strict validation report the real defect.
            payload["run_manifest_hash"] = "0" * 64
    return RunManifest.model_validate(payload)


def sample_normalized_provenance(**overrides: Any) -> NormalizedResultProvenance:
    """The twelve required provenance items of specification 20.2 over the
    doubles' identities; an override whose value is ``MISSING`` removes the key."""
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "experiment_id": EXPERIMENT_ID,
        "experiment_spec_hash": RUNNING_EXPERIMENT.spec_hash,
        "run_id": RUN_ID,
        "attempt_number": 1,
        "attempt_token_hash": ATTEMPT_TOKEN_HASH,
        "invocation_id": INVOCATION_ID,
        "engine": ENGINE_ALPHA,
        "adapter": ADAPTER_ALPHA,
        "converter_name": "core.converter",
        "converter_version": "1.0.0",
        "source_artifact_id": ARTIFACT_ID,
        "source_artifact_hash": "a" * 64,
        "canonical_schema_version": "1.0.0",
        "protocol_version": "1.0.0",
        "strategy_version_hash": STRATEGY_HASH,
        "dataset_version_hash": DATASET_HASH,
        "approximations": (),
        "normalized_at_utc": INSTANT,
        "validation_profile": "artifact-validation/v1",
    }
    payload.update(overrides)
    return NormalizedResultProvenance.model_validate(_without_missing(payload))


# --------------------------------------------------------------------------
# Task 6 (plan 7.1): the finalization fixture over SQLite
# --------------------------------------------------------------------------

_CANCELLATION_CODE: Final = "PROCESS.CANCELLED"
_VERDICT_FAILURE_CODE: Final = "ENGINE.RUNTIME_FAILURE"
_FIXTURE_REASON: Final = "TEST.FINALIZATION_FIXTURE"
_CANCEL_CORRELATION: Final = "cancel-task7"
#: The one declared metric of a production RESULT pre-state (a ``ratio`` so the
#: registrar's unit projection runs on a mapped unit).
_DECLARED_METRIC: Final[Mapping[str, Any]] = {
    "metric_name": "total-return",
    "value": Decimal("0.125"),
    "value_status": "DEFINED",
    "unit": "ratio",
    "methodology_version": "1.0.0",
    "comparison_level": ComparisonLevel.LEVEL_2,
}


def _event_id_for(invocation_id: str, sequence: int) -> str:
    """A ledger event identity derived from the invocation and the sequence, so
    two attempts' ledgers never share one (``append_event`` keys on it)."""
    return f"evt_{_uuid4_shaped(sha256_bytes(f'{invocation_id}:{sequence}'.encode()))}"


def _run_event(
    run: EngineRunRecord,
    invocation_id: str,
    sequence: int,
    event_type: ProtocolEventType,
    payload: ArtifactProducedPayload | FinalResultPayload,
    *,
    now_utc: datetime,
) -> RunEvent:
    """One sanitized ledger event with its content hash recomputed (the
    ``persistence_support.harness.sample_run_event`` idiom)."""
    fields: dict[str, Any] = {
        "schema_version": "1.0.0",
        "protocol_version": "1.0.0",
        "event_id": _event_id_for(invocation_id, sequence),
        "invocation_id": invocation_id,
        "run_id": run.run_id,
        "attempt_token_hash": run.attempt_token_hash,
        "sequence": sequence,
        "event_type": event_type,
        "timestamp_utc": now_utc + timedelta(seconds=sequence),
        "payload": payload,
        "received_at_utc": now_utc + timedelta(seconds=sequence, microseconds=1),
        "wire_event_hash": sha256_bytes(canonical_json_bytes(payload)),
    }
    draft = RunEvent.model_construct(**fields, content_hash="0" * 64)
    return RunEvent.model_validate(
        {**fields, "content_hash": run_event_content_hash(draft)}
    )


class FinalizationFixture:
    """Plan 7.1: ``ArtifactStoreFixture``, the migrated test database,
    ``SqliteUnitOfWork``, the registrar, validator and auditor, and
    ``CoreArtifactFinalizer`` composed under one ``tmp_path``.

    By default the Task 6 doubles are composed (``MemoryRegistrar``,
    ``MemoryRecoveryValidator``, ``FactAuditor`` over ``SequentialAuditIds``):
    the registrar records evidence links only and refuses every RESULT
    registration, and the validator answers planted facts, so RESULT success is
    unreachable by construction. ``production=True`` composes Task 7's
    ``ResultRegistrar``, ``ResultRecoveryValidator`` and ``AuditFactRecorder``
    over the same database, and ``plant_result_prestate`` then plants the real
    adapter wire (``plant_production_result``), so the RESULT cells that end in
    ``REGISTERED`` success are proven here. The probe is per call, so
    ``recover()`` -- always ``NoProbe()`` -- never re-trips a crashing probe.
    ``reopen()`` closes and reopens the database and keeps every root (the
    production validator, which holds a unit of work over the database, is
    rebuilt), so a crash-point test asserts durable state through a fresh
    connection; ``open(..., reuse=True)`` composes over an existing layout (the
    crash child's entry point).
    """

    def __init__(
        self,
        tmp_path: Path,
        *,
        clock: FixedClock,
        reuse: bool,
        hasher: StreamingContentHasher | None = None,
        production: bool = False,
    ) -> None:
        self.tmp_path = tmp_path
        self.clock = clock
        self.production = production
        self.hasher = hasher if hasher is not None else StreamingContentHasher()
        self.roots = ArtifactStoreFixture(
            tmp_path, clock=clock, hasher=self.hasher, reuse=reuse
        )
        self.database = open_test_database(tmp_path, clock=clock)
        self.harness = ArtifactHarness(self.database)
        # A fixture composed over an existing layout (the parent after the crash
        # child) draws its audit identifiers from a seed the earlier process
        # never used, so a committed row of that process is never re-identified.
        committed = len(self.harness.committed_audit_events()) if reuse else 0
        seed = "task6-sqlite" if not reuse else f"task6-sqlite-reopen-{committed}"
        self.audit_ids = SequentialAuditIds(seed)
        self.auditor: FinalizationAuditor
        self.registrar: PurposeRegistrar
        self.validator: ResultRecoveryValidatorPort
        if production:
            self.auditor = AuditFactRecorder(self.audit_ids, clock)
            # The registrar reads the canonical evidence facts through the
            # fixture's ``begin``, which resolves the current database at every
            # call, so the same registrar serves across ``reopen``.
            self.registrar = ResultRegistrar(
                self.auditor, clock, transactions=self.begin
            )
            self.validator = self._production_validator()
        else:
            self.auditor = FactAuditor(self.audit_ids, clock)
            self.registrar = MemoryRegistrar()
            self.validator = MemoryRecoveryValidator(clock)
        self.log = RecordingLog()
        self.prestate: ResultPrestate | None = None
        self._command_roots: dict[str, CommandRootPaths] = {}
        if reuse:
            self._rediscover_command_roots()

    @classmethod
    def open(
        cls,
        tmp_path: Path,
        *,
        clock: FixedClock,
        reuse: bool = False,
        hasher: StreamingContentHasher | None = None,
        production: bool = False,
    ) -> FinalizationFixture:
        return cls(
            tmp_path, clock=clock, reuse=reuse, hasher=hasher, production=production
        )

    # -- composition -----------------------------------------------------------

    def _production_validator(self) -> ProductionRecoveryValidator:
        """The Task 7 validator over a unit of work of the current database; the
        registrar it remembers a regenerated sanitized manifest into is the
        production one composed here."""
        registrar = self.registrar
        return ProductionRecoveryValidator(
            unit_of_work=self.unit_of_work(),
            hasher=self.hasher,
            negotiated_versions=DEFAULT_NEGOTIATED_VERSIONS,
            finalization_timeout_seconds=RESULT_TIMEOUT_SECONDS,
            clock=self.clock,
            registrar=registrar if isinstance(registrar, ResultRegistrar) else None,
        )

    @property
    def memory_registrar(self) -> MemoryRegistrar:
        """The Task 6 registrar double (the default composition)."""
        assert isinstance(self.registrar, MemoryRegistrar), type(self.registrar)
        return self.registrar

    @property
    def memory_validator(self) -> MemoryRecoveryValidator:
        """The Task 6 validator double (the default composition)."""
        assert isinstance(self.validator, MemoryRecoveryValidator), type(self.validator)
        return self.validator

    def _rediscover_command_roots(self) -> None:
        """The command roots an earlier fixture planted under the runtime root."""
        for child in sorted(self.roots.runtime_root.iterdir()):
            if not child.is_dir() or not child.name.startswith("inv_"):
                continue
            runs = child / "runs"
            if not runs.is_dir():
                continue
            for run_dir in sorted(runs.iterdir()):
                work_dir = run_dir / "work"
                self._command_roots[child.name] = CommandRootPaths(
                    command_root=child,
                    request_path=child / "request.json",
                    work_dir=work_dir,
                    result_path=work_dir / "adapter-result-manifest.json",
                )

    def command_roots(self, invocation_id: str) -> CommandRootPaths | MISSING:  # type: ignore[valid-type]
        return self._command_roots.get(invocation_id, MISSING)

    def token_material(self, invocation_id: str) -> AttemptTokenMaterial | MISSING:  # type: ignore[valid-type]
        roots = self._command_roots.get(invocation_id)
        if roots is None or not roots.request_path.is_file():
            return MISSING
        work_dir = roots.work_dir
        run_id = work_dir.parent.name if isinstance(work_dir, Path) else RUN_ID
        return read_token_material(roots, run_id=run_id)

    def unit_of_work(self) -> SqliteUnitOfWork:
        return self.harness.unit_of_work()

    def begin(self) -> SqliteTransaction:
        """The unit-of-work factory the finalizer and the reconciler call."""
        return self.unit_of_work().begin()

    def finalizer(
        self,
        probe: FinalizationProbe | None = None,
        *,
        log: FinalizationLog | None = None,
        registrar: PurposeRegistrar | None = None,
    ) -> CoreArtifactFinalizer:
        return CoreArtifactFinalizer(
            self.begin,
            self.clock,
            self.hasher,
            self.roots.store,
            probe if probe is not None else RecordingProbe(),
            registrar if registrar is not None else self.registrar,
            self.auditor,
            command_roots=self.command_roots,
            token_material=self.token_material,
            log=log,
        )

    # -- planting --------------------------------------------------------------

    def plant_run(
        self,
        *,
        run_state: EngineRunState = EngineRunState.RUNNING,
        invocation_state: CommandInvocationState = CommandInvocationState.EXITED,
        experiment_state: ExperimentState = ExperimentState.RUNNING,
    ) -> ResultPrestate:
        """The section 5 pre-state rows: experiment, observation, the run (no
        deadline: the finalizer snapshots it), the run-command invocation and the
        owner rows."""
        put_experiment(self.harness.lifecycle(), sample_experiment(experiment_state))
        self.prestate = self.harness.seed_result_prestate(
            run_state=run_state, deadline=None, invocation_state=invocation_state
        )
        return self.prestate

    def plant_result_prestate(
        self,
        *,
        files: Mapping[str, bytes] = RESULT_FILES,
        candidate_state: CandidateArtifactState = CandidateArtifactState.CANDIDATE,
        **request_overrides: Any,
    ) -> ResultPlan:
        """The section 5 RESULT pre-state: the rows, the work directory files,
        ``request.json`` with the fixture token, two ``CANDIDATE`` rows and the
        request. A production fixture plants the real adapter wire
        (``plant_production_result``); the default plants the Task 6 stub
        manifest the memory validator never reads."""
        if self.production:
            return self.plant_production_result(
                files=files, candidate_state=candidate_state, **request_overrides
            )
        prestate = self.prestate if self.prestate is not None else self.plant_run()
        roots = plant_command_root(
            self.roots.runtime_root,
            run_id=prestate.run.run_id,
            invocation_id=prestate.invocation.invocation_id,
            files=files,
        )
        self._command_roots[prestate.invocation.invocation_id] = roots
        candidates = result_candidates(files=files, state=candidate_state)
        for candidate in candidates:
            self.harness.put_candidate(candidate)
        request = sample_result_request(
            [candidate.candidate_artifact_id for candidate in candidates],
            run=prestate.run,
            invocation=prestate.invocation,
            **request_overrides,
        )
        return ResultPlan(
            run=prestate.run,
            invocation=prestate.invocation,
            candidates=candidates,
            roots=roots,
            request=request,
        )

    def plant_attempt(
        self,
        *,
        run_id: str,
        invocation_id: str,
        attempt_number: int,
        predecessor_run_id: str,
    ) -> ResultPrestate:
        """A later attempt of the planted run's slot (RC-16): its ``RUNNING`` row
        naming the predecessor, its ``EXITED`` run-command invocation and its
        ``RUN`` owner row. The predecessor must already be terminal."""
        run = sample_run(
            EngineRunState.RUNNING,
            run_id=run_id,
            attempt_number=attempt_number,
            predecessor_run_id=predecessor_run_id,
        )
        put_run(self.harness.lifecycle(), run)
        invocation = sample_invocation(
            CommandInvocationState.EXITED,
            kind=CommandKind.RUN,
            invocation_id=invocation_id,
            run_id=run_id,
        )
        put_invocation(self.harness.lifecycle(), invocation)
        owner = RunArtifactOwner(
            owner_kind="RUN",
            experiment_id=run.experiment_id,
            run_id=run_id,
            invocation_id=invocation_id,
        )
        owner_hash = self.harness.put_owner(owner)
        return ResultPrestate(
            run=run, invocation=invocation, owners=(owner,), owner_hashes=(owner_hash,)
        )

    def plant_production_result(
        self,
        prestate: ResultPrestate | None = None,
        *,
        files: Mapping[str, bytes] = RESULT_FILES,
        candidate_state: CandidateArtifactState = CandidateArtifactState.CANDIDATE,
        token: str = FIXTURE_TOKEN,
        sanitized_row: bool = True,
        plant_candidates: bool = True,
        **request_overrides: Any,
    ) -> ProductionResultPlan:
        """The Task 7 RESULT pre-state (plan 4.4 after step 2, before the RESULT
        lease): the rows of ``prestate`` (the planted run by default), the work
        directory files, ``request.json`` carrying ``token``, the adapter result
        manifest declaring every file with the provenance the run and experiment
        reconcile against, the ``ARTIFACT_PRODUCED`` and ``FINAL_RESULT`` ledger
        appended through ``engine_runs.append_event``, one ``CANDIDATE`` row per
        file naming its accepted event (unless ``plant_candidates`` is false:
        the plan 4.4 step-2 registration then creates them), the sanitized row
        (unless ``sanitized_row`` is false: recovery then regenerates it) and the
        request whose source and sanitized hashes derive from those bytes."""
        if prestate is None:
            prestate = self.prestate if self.prestate is not None else self.plant_run()
        run = prestate.run
        invocation_id = prestate.invocation.invocation_id
        now = self.clock.now_utc()
        declarations = tuple(
            ArtifactProducedPayload(
                relative_path=relative,
                artifact_kind=NATIVE_KIND,
                media_type=NATIVE_MEDIA,
                declared_size_bytes=len(data),
                declared_sha256=sha256_bytes(data),
            )
            for relative, data in files.items()
        )
        manifest = AdapterResultManifest.model_validate(
            {
                "schema_version": "1.0.0",
                "protocol_version": "1.0.0",
                "adapter_manifest_id": ADAPTER_MANIFEST_ID,
                "experiment_id": run.experiment_id,
                "run_id": run.run_id,
                "invocation_id": invocation_id,
                "attempt_token": token,
                "semantic_status": SemanticStatus.SUCCEEDED,
                "started_at_utc": now + timedelta(seconds=2),
                "completed_at_utc": now + timedelta(seconds=9),
                "provenance": sample_run_provenance(
                    request_hash=run.request_hash,
                    adapter=run.adapter,
                    engine=run.engine,
                    logical_slot_id=run.logical_slot_id,
                    attempt_number=run.attempt_number,
                ),
                "candidate_artifacts": tuple(
                    {
                        "relative_path": item.relative_path,
                        "artifact_kind": item.artifact_kind,
                        "media_type": item.media_type,
                        "declared_size_bytes": item.declared_size_bytes,
                        "declared_sha256": item.declared_sha256,
                    }
                    for item in declarations
                ),
                "candidate_metrics": (dict(_DECLARED_METRIC),),
                "diagnostics": (),
                "warnings": (),
                "approximations": (),
            }
        )
        manifest_bytes = canonical_json_bytes(manifest)
        roots = plant_command_root(
            self.roots.runtime_root,
            run_id=run.run_id,
            invocation_id=invocation_id,
            token=token,
            files=files,
            manifest=manifest_bytes,
        )
        self._command_roots[invocation_id] = roots
        events = [
            _run_event(
                run,
                invocation_id,
                sequence,
                ProtocolEventType.ARTIFACT_PRODUCED,
                declaration,
                now_utc=now,
            )
            for sequence, declaration in enumerate(declarations, start=1)
        ]
        events.append(
            _run_event(
                run,
                invocation_id,
                len(events) + 1,
                ProtocolEventType.FINAL_RESULT,
                FinalResultPayload(
                    manifest_relative_path=RESULT_MANIFEST_RELATIVE_PATH,
                    source_adapter_result_manifest_hash=sha256_bytes(manifest_bytes),
                    semantic_status=manifest.semantic_status,
                ),
                now_utc=now,
            )
        )
        transaction = self.begin()
        for event in events:
            ok(transaction.engine_runs.append_event(event))
        commit(transaction)
        parse = parse_result_manifest(
            manifest_bytes, max_bytes=MAX_RESULT_MANIFEST_BYTES, token=token
        )
        summary = InvocationEventLedger.from_events(tuple(events)).summary()
        sanitized = sanitize_result_manifest(parse, summary)
        if sanitized_row:
            self.harness.put_sanitized_manifest(
                SanitizedManifestFacts(
                    sanitized_adapter_result_manifest_hash=(
                        sanitized.sanitized_adapter_result_manifest_hash
                    ),
                    run_id=run.run_id,
                    run_invocation_id=invocation_id,
                    experiment_id=run.experiment_id,
                    attempt_token_hash=sanitized.attempt_token_hash,
                    source_adapter_result_manifest_hash=parse.source_hash,
                    semantic_status=sanitized.semantic_status.value,
                    manifest_json=canonical_json_text(sanitized),
                    evidence_artifact_id=MISSING,
                    recorded_at_utc=now,
                )
            )
        owner = next(
            (
                item
                for item in prestate.owners
                if isinstance(item, RunArtifactOwner)
                and item.run_id == run.run_id
                and item.invocation_id == invocation_id
            ),
            RUN_OWNER,
        )
        event_ids = {
            record.payload.relative_path: record.event_id
            for record in summary.artifact_declarations
        }
        candidates = tuple(
            candidate.model_copy(
                update={"source_event_id": event_ids[candidate.staging_relative_path]}
            )
            for candidate in result_candidates(
                run_id=run.run_id,
                invocation_id=invocation_id,
                owner=owner,
                files=files,
                state=candidate_state,
            )
        )
        if plant_candidates:
            for candidate in candidates:
                self.harness.put_candidate(candidate)
        request = sample_result_request(
            [candidate.candidate_artifact_id for candidate in candidates],
            run=run,
            invocation=prestate.invocation,
            owner=owner,
            source_hash=parse.source_hash,
            sanitized_hash=sanitized.sanitized_adapter_result_manifest_hash,
            **request_overrides,
        )
        return ProductionResultPlan(
            run=run,
            invocation=prestate.invocation,
            candidates=candidates,
            roots=roots,
            request=request,
            manifest_bytes=manifest_bytes,
            events=tuple(events),
            parse=parse,
            summary=summary,
            sanitized=sanitized,
        )

    def result_request_for(
        self, owner: RunArtifactOwner = RUN_OWNER
    ) -> ResultFinalizationRequest:
        """The RESULT request over the committed ``CANDIDATE`` rows of ``owner``
        at the current run and invocation revisions, its hashes regenerated by
        the composed validator from the surviving root (the crash child rebuilds
        its request from the planted state, as recovery does)."""
        invocation_id = str(owner.invocation_id)
        roots = self._command_roots[invocation_id]
        transaction = self.begin()
        try:
            listed = ok(
                transaction.candidate_artifacts.list_recoverable(
                    (
                        CandidateArtifactState.CANDIDATE,
                        CandidateArtifactState.VALIDATING,
                    ),
                    owner,
                )
            )
            run = ok(transaction.engine_runs.get(owner.run_id))
            invocation = ok(transaction.command_invocations.get(invocation_id))
        finally:
            transaction.rollback()
        facts = ok(
            self.validator.validate_temporary_manifest(
                roots, self.token_material(invocation_id), tuple(listed)
            )
        )
        return sample_result_request(
            [candidate.candidate_artifact_id for candidate in listed],
            run=run,
            invocation=invocation,
            owner=owner,
            source_hash=facts.source_adapter_result_manifest_hash,
            sanitized_hash=facts.sanitized_adapter_result_manifest_hash,
            timeout_seconds=facts.finalization_timeout_seconds,
        )

    def plant_evidence_prestate(
        self,
        owner: ArtifactOwnerRef = RUN_OWNER,
        *,
        correlation: EvidenceCorrelation = INVOCATION_CORRELATION,
        files: Mapping[str, bytes] = EVIDENCE_FILES,
        with_run: bool = True,
        **request_overrides: Any,
    ) -> EvidencePlan:
        if with_run and self.prestate is None:
            self.plant_run()
        candidates = plant_core_evidence(
            self.roots.store, owner=owner, correlation=correlation, files=files
        )
        for candidate in candidates:
            self.harness.put_candidate(candidate)
        request = sample_evidence_request(
            [candidate.candidate_artifact_id for candidate in candidates],
            owner=owner,
            correlation=correlation,
            **request_overrides,
        )
        return EvidencePlan(owner=owner, candidates=candidates, request=request)

    def evidence_request_for(
        self, owner: ArtifactOwnerRef = RUN_OWNER, *, correlation: EvidenceCorrelation
    ) -> EvidenceFinalizationRequest:
        """The EVIDENCE request over the committed ``CANDIDATE`` rows of ``owner``
        (the crash child rebuilds its request from the planted rows)."""
        transaction = self.begin()
        try:
            listed = ok(
                transaction.candidate_artifacts.list_recoverable(
                    (
                        CandidateArtifactState.CANDIDATE,
                        CandidateArtifactState.VALIDATING,
                    ),
                    owner,
                )
            )
        finally:
            transaction.rollback()
        return sample_evidence_request(
            [candidate.candidate_artifact_id for candidate in listed],
            owner=owner,
            correlation=correlation,
        )

    # -- driving -----------------------------------------------------------------

    def finalize(
        self,
        request: ResultFinalizationRequest | EvidenceFinalizationRequest,
        *,
        probe: FinalizationProbe | None = None,
        cancellation: FlagCancellationToken | None = None,
        log: FinalizationLog | None = None,
        registrar: PurposeRegistrar | None = None,
    ) -> Result[FinalizationResult]:
        token = cancellation if cancellation is not None else FlagCancellationToken()
        finalizer = self.finalizer(probe, log=log, registrar=registrar)
        return run_coroutine(finalizer.finalize(request, token))

    def finalize_result(
        self, plan: ResultPlan, *, probe: FinalizationProbe | None = None
    ) -> Result[FinalizationResult]:
        return self.finalize(plan.request, probe=probe)

    def finalize_evidence(
        self, plan: EvidencePlan, *, probe: FinalizationProbe | None = None
    ) -> Result[FinalizationResult]:
        return self.finalize(plan.request, probe=probe)

    def recover(self) -> Result[FinalizationReconciliationReport]:
        return reconcile_finalization(
            unit_of_work_factory=self.begin,
            store=self.roots.store,
            hasher=self.hasher,
            registrar=self.registrar,
            recovery_validator=self.validator,
            auditor=self.auditor,
            clock=self.clock,
            runtime_root=self.roots.runtime_root,
            command_roots=self.command_roots,
            token_material=self.token_material,
            log=self.log,
        )

    def advance_clock(self, seconds: float) -> None:
        self.clock.advance(seconds)

    def reopen(self) -> None:
        """Close the database and reopen it on the same path; every root and the
        command roots stay (plan 7.1). A production validator holds a unit of
        work over the closed database and is rebuilt over the reopened one."""
        self.harness.close()
        self.database = open_test_database(self.tmp_path, clock=self.clock)
        self.harness = ArtifactHarness(self.database)
        if self.production:
            self.validator = self._production_validator()

    def close(self) -> None:
        self.harness.close()

    # -- the Stage 5 run writes the races use -------------------------------------

    def current_run(self, run_id: str = RUN_ID) -> EngineRunRecord:
        runs = [
            run
            for run in self.harness.lifecycle().committed_engine_runs()
            if run.run_id == run_id
        ]
        assert len(runs) == 1, runs
        return runs[0]

    def cancel_run(self, run_id: str = RUN_ID) -> EngineRunRecord:
        """The Stage 5 ``transition_run(RUNNING -> CANCELLED)`` with a recorded
        ``CANCELLATION`` diagnostic naming the invocation (reading 23)."""
        return self._transition(
            run_id,
            EngineRunState.CANCELLED,
            sample_diagnostic(
                DIAG_ID,
                error_code=_CANCELLATION_CODE,
                category=DiagnosticCategory.CANCELLATION,
                retriable=False,
            ),
        )

    def fail_run_by_verdict(self, run_id: str = RUN_ID) -> EngineRunRecord:
        """The run moved ``RUNNING -> FAILED`` by a verdict (RC-14's pre-state)."""
        return self._transition(
            run_id,
            EngineRunState.FAILED,
            sample_diagnostic(
                OTHER_DIAG_ID,
                error_code=_VERDICT_FAILURE_CODE,
                category=DiagnosticCategory.ENGINE_RUNTIME,
                retriable=False,
            ),
        )

    def _transition(
        self, run_id: str, target: EngineRunState, diagnostic: Diagnostic
    ) -> EngineRunRecord:
        return ok(self.try_transition_run(run_id, target, diagnostic))

    def try_transition_run(
        self, run_id: str, target: EngineRunState, diagnostic: Diagnostic
    ) -> Result[EngineRunRecord]:
        """The Stage 5 generic ``transition_run`` of the current run row to
        ``target`` under ``diagnostic`` (recorded first), as the operation
        answers it -- a refusal is returned, not asserted (RC-3, RC-9)."""
        recorder = SqliteDiagnosticRecorder(self.database, clock=self.clock)
        ok(recorder.record(diagnostic))
        run = self.current_run(run_id)
        # The Stage 5 operation stamps ``updated_at_utc`` from its clock, which
        # never moves backwards past the planted row's own instant.
        operation_clock = FixedClock(max(self.clock.now_utc(), run.updated_at_utc))
        return transition_run(
            RunTransitionRequest(
                schema_version="1.0.0",
                run_id=run_id,
                expected_revision=run.revision,
                target_state=target,
                reason_code=_FIXTURE_REASON,
                primary_terminal_diagnostic_id=diagnostic.diagnostic_id,
            ),
            unit_of_work=self.unit_of_work(),
            clock=operation_clock,
        )

    def current_experiment(
        self, experiment_id: str = EXPERIMENT_ID
    ) -> ExperimentRecord:
        experiments = [
            experiment
            for experiment in self.harness.lifecycle().committed_experiments()
            if experiment.experiment_id == experiment_id
        ]
        assert len(experiments) == 1, experiments
        return experiments[0]

    def cancel_experiment(
        self, experiment_id: str = EXPERIMENT_ID
    ) -> Result[ExperimentRecord]:
        """The Stage 5 ``cancel_experiment`` over the current experiment row: it
        swaps the experiment to ``CANCELLED`` and reads no run (reading 23;
        RC-3, RC-17)."""
        experiment = self.current_experiment(experiment_id)
        operation_clock = FixedClock(
            max(self.clock.now_utc(), experiment.updated_at_utc)
        )
        return cancel_experiment(
            CancelExperimentRequest(
                schema_version="1.0.0",
                experiment_id=experiment_id,
                expected_revision=experiment.revision,
                correlation_id=_CANCEL_CORRELATION,
            ),
            unit_of_work=self.unit_of_work(),
            clock=operation_clock,
        )

    # -- the durable snapshot ----------------------------------------------------

    def committed_diagnostics(self) -> tuple[Diagnostic, ...]:
        statement = select(DiagnosticRow).order_by(DiagnosticRow.diagnostic_id)
        return tuple(
            ok(decode_diagnostic(row, clock=self.clock))
            for row in self.harness._rows(statement)
        )

    def durable(self, run_id: str = RUN_ID) -> DurableState:
        """Every Stage 9 table beside the run and invocation rows, the filesystem
        listing and the audit rows, through fresh read-only sessions (plan 7.1)."""
        runs = [
            run
            for run in self.harness.lifecycle().committed_engine_runs()
            if run.run_id == run_id
        ]
        invocations = [
            invocation
            for invocation in self.harness.lifecycle().committed_command_invocations()
            if invocation.run_id == run_id
            and invocation.command_kind is CommandKind.RUN
        ]
        return DurableState(
            journal=self.harness.committed_journal(),
            candidates=self.harness.committed_candidates(),
            refs=self.harness.committed_refs(),
            run=runs[0] if runs else None,
            invocation=invocations[0] if invocations else None,
            run_manifests=self.harness.committed_run_manifests(),
            run_artifacts=self.harness.committed_run_artifacts(),
            audit_events=self.harness.committed_audit_events(),
            diagnostics=self.committed_diagnostics(),
            object_blobs=self.roots.object_blobs(),
            staging_files=self.roots.staging_files(),
            command_root_files=self.roots.command_root_files(),
            quarantine_entries=self.roots.quarantine_entries(),
        )


# --------------------------------------------------------------------------
# Task 8 (plan 7.1, 4.4, 4.6, 5): the finalizing supervised flow
# --------------------------------------------------------------------------
#
# ``FinalizingSupervisedFlow`` extends the Stage 8 ``SupervisedSqliteFlow`` with
# the Stage 9 composition. It lives here rather than in ``supervised.py`` because
# the Stage 8 import pin (``test_stage8_supervised_flow.py``) holds that module's
# import set exactly and the plan keeps that test unchanged (plan 7.4): the Stage 9
# members are a subclass over the Stage 8 flow, whose one Stage 8 change is the
# ``keep_command_roots`` keyword of ``close`` (plan 7.1), with no new import. The
# composition is the production one throughout -- ``observe_candidates`` before the
# verdict,
# ``semantic_outcome_or_replay``, ``conclude_command`` and ``conclude_describe``
# over ``CoreArtifactFinalizer`` with ``ResultRegistrar``, ``AuditFactRecorder``
# and ``ResultRecoveryValidator``, then ``reconcile_invocations`` followed by
# ``reconcile_finalization`` for recovery -- and the flow adds only what a test
# needs around it: the roots, the probe, the durable readers, the token scan.
#
# Declared readings: the supervision root is the Stage 9 runtime root (the
# reconciler lists ``inv_*`` command roots there and skips the reserved
# ``staging`` and ``quarantine`` segments beside them); every
# ``SupervisionTraceEntry`` is projected as a ``LogRecord`` through the audit
# package's JSON Lines writer -- the log record is an audit contract (reading
# 15) and the closed ``AuditAction`` vocabulary names no supervision action, so
# an ``AuditEvent`` projection would have to fabricate one; the finalizing
# configuration pins ``finalization_timeout_seconds`` above the compiled lease
# so a crash cell's lease can expire inside its deadline (the ruling of
# 2026-11-08); the audit identifiers of a (re)opened flow are seeded from the
# committed audit row count so no committed identifier is minted twice.

#: The finalization timeout the Stage 9 flow pins: above ``RESULT_LEASE_SECONDS``
#: (300), so an expired lease can be taken over before the deadline passes.
FINALIZATION_TIMEOUT_SECONDS: Final = 600
FINALIZING_CONFIG: Final = ApplicationConfig(
    process=ProcessConfig(finalization_timeout_seconds=FINALIZATION_TIMEOUT_SECONDS)
)
#: The Stage 8 rows plus the warning and checksum-mismatch rows Task 8 drives.
STAGE9_SUPERVISED_ROW_NAMES: Final = frozenset(
    {
        "row01-conformant-describe",
        "row02-conformant-validate",
        "row03-conformant-run",
        "row04-warnings-run",
        "row05-unsupported-capability-validate",
        "row26-process-timeout-run",
        "row27-cancellation-run",
        "row28-exit-40-run",
        "row36-checksum-mismatch-run",
    }
)
_STAGE9_SCENARIO_BY_NAME: Final[dict[str, Scenario]] = {
    item.name: item for item in SCENARIOS
}
_AUDIT_SEED: Final = "stage9-supervised"
_LOG_COMPONENT: Final = "persistence-support.finalizing-flow"
_TRACE_EVENT_PREFIX: Final = "SUPERVISION"
_DATABASE_SEGMENT: Final = "db"
_SUPERVISION_SEGMENT: Final = "sv"
_STAGING_SEGMENT: Final = "staging"
_QUARANTINE_SEGMENT: Final = "quarantine"
_ARTIFACTS_SEGMENT: Final = "artifacts"
_LOGS_SEGMENT: Final = "logs"
_REQUEST_FILE_NAME: Final = "request.json"
_OUTPUT_FILE_NAME: Final = "output.json"
_RUNS_SEGMENT: Final = "runs"
_WORK_SEGMENT: Final = "work"
_COMMAND_ROOT_PREFIX: Final = "inv_"
_JSON_COLUMN_SUFFIX: Final = "_json"
_USER_TABLES_SQL: Final = (
    "SELECT name FROM sqlite_master WHERE type = 'table' "
    "AND name NOT LIKE 'sqlite_%' ORDER BY name"
)
_PROBE_POINTS: Final = (
    "before_prepared",
    "after_prepared",
    "before_move",
    "after_move",
    "before_moved",
    "after_moved",
    "before_registered",
    "inside_registered",
    "after_registered",
    "after_close",
)


@dataclass(frozen=True, slots=True)
class DescribeConclusion(DescribeOutcome):
    """S-1's products plus plan 4.6: the ``ADAPTER``-owned evidence references
    ``conclude_describe`` finalized (the descriptor and the stderr capture)."""

    evidence_refs: tuple[ArtifactRef, ...]


@dataclass(frozen=True, slots=True)
class RecoveryReports:
    """One ``recover()``: the Stage 7 process reconciliation first, then the
    Stage 9 artifact reconciliation."""

    process: ReconciliationReport
    artifacts: FinalizationReconciliationReport


@dataclass(frozen=True, slots=True)
class TokenScanReport:
    """One ``scan_for_token``: how many files or cells each surface held and
    every surface location that carried the raw token."""

    surfaces: Mapping[str, int]
    hits: tuple[str, ...]


class ClockAdvancingProbe:
    """A ``FinalizationProbe`` that advances the flow's ``FixedClock`` the first
    time one named point is reached (RC-4: the deadline passes between
    ``after_moved`` and T3 of the RESULT finalization; the conclusion's later
    evidence finalization, which shares the probe, is left alone)."""

    def __init__(self, point: str, clock: FixedClock, seconds: float) -> None:
        if point not in _PROBE_POINTS:
            raise ValueError(f"{point} is not a probe point")
        self._point = point
        self._clock = clock
        self._seconds = seconds
        self.fired = 0
        self.reached = 0

    def _at(self, point: str) -> None:
        if point != self._point:
            return
        self.reached += 1
        if self.fired == 0:
            self._clock.advance(self._seconds)
            self.fired += 1

    def before_prepared(self) -> None:
        self._at("before_prepared")

    def after_prepared(self) -> None:
        self._at("after_prepared")

    def before_move(self, index: int) -> None:
        del index
        self._at("before_move")

    def after_move(self, index: int) -> None:
        del index
        self._at("after_move")

    def before_moved(self) -> None:
        self._at("before_moved")

    def after_moved(self) -> None:
        self._at("after_moved")

    def before_registered(self) -> None:
        self._at("before_registered")

    def inside_registered(self) -> None:
        self._at("inside_registered")

    def after_registered(self) -> None:
        self._at("after_registered")

    def after_close(self) -> None:
        self._at("after_close")


class JsonLinesFinalizationLog:
    """The flow's ``FinalizationLog`` over the audit package's JSON Lines writer,
    and the O-13 stand-in: every ``SupervisionTraceEntry`` is projected as a
    ``LogRecord`` carrying the entry's own facts (redacted to the fixed point),
    never as an ``AuditEvent`` of a borrowed action. A projection, never a
    record of truth (specification 30.1)."""

    __slots__ = ("_clock", "_writer", "lines")

    def __init__(self, writer: JsonLinesLogWriter, clock: Clock) -> None:
        self._writer = writer
        self._clock = clock
        self.lines = 0

    def write(self, fact: LogFact) -> Result[None]:
        payload: dict[str, Any] = {
            "schema_version": "1.0.0",
            "timestamp_utc": self._clock.now_utc(),
            "severity": LogSeverity(fact.severity),
            "component": _LOG_COMPONENT,
            "event_code": fact.event_code,
            "correlation_id": fact.correlation_id,
            "message": (
                REDACTED if contains_token_shape(fact.message) else fact.message
            ),
            "details": redact_details(dict(fact.details)),
        }
        for name in ("experiment_id", "run_id", "invocation_id"):
            value = getattr(fact, name)
            if isinstance(value, str):
                payload[name] = value
        return self._write(payload)

    def project_trace(self, entries: Sequence[SupervisionTraceEntry]) -> int:
        """Plan Task 8 and O-13: one line per trace entry, the entry's kind as the
        event code, its facts (and ordinal readings) as the details."""
        for entry in entries:
            facts: dict[str, Any] = dict(entry.facts)
            facts["sequence"] = entry.sequence
            facts["monotonic_100ns"] = entry.monotonic_100ns
            ok(
                self._write(
                    {
                        "schema_version": "1.0.0",
                        "timestamp_utc": entry.at_utc,
                        "severity": LogSeverity.INFO,
                        "component": _LOG_COMPONENT,
                        "event_code": f"{_TRACE_EVENT_PREFIX}.{entry.kind.value}",
                        "correlation_id": entry.invocation_id,
                        "invocation_id": entry.invocation_id,
                        "message": (
                            f"supervision trace {entry.sequence}: {entry.kind.value}"
                        ),
                        "details": redact_details(facts),
                    }
                )
            )
        return len(entries)

    def _write(self, payload: Mapping[str, Any]) -> Result[None]:
        try:
            record = LogRecord.model_validate(dict(payload))
        except ValidationError as error:
            # The locations and messages name fields and grammars, never values.
            reasons = "; ".join(
                f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}"
                for item in error.errors(include_input=False, include_url=False)
            )
            return log_write_failure(
                f"log record could not be validated: {reasons}",
                now_utc=self._clock.now_utc(),
            )
        written = self._writer.write(record)
        if not isinstance(written, Failure):
            self.lines += 1
        return written

    def close(self) -> None:
        self._writer.close()


def _files_under(root: Path) -> tuple[Path, ...]:
    """Every regular file under ``root`` (none when the root is absent), sorted."""
    if not root.is_dir():
        return ()
    return tuple(path for path in sorted(root.rglob("*")) if path.is_file())


def _hash_envelope_bytes(profile: HashingProfile, payload: dict[str, Any]) -> bytes:
    """The exact bytes ``profile_hash`` digests: the canonical JSON of the
    ``CanonicalHashEnvelope`` over ``payload`` (``domain/hashing.py``)."""
    return canonical_json_bytes(
        CanonicalHashEnvelope(
            schema_version="1.0.0", hashing_profile=profile, payload=payload
        )
    )


def configuration_audit_bytes(snapshot: ConfigSnapshot) -> bytes:
    """The bytes whose SHA-256 is the frozen ``configuration_audit_hash``: the
    ``CONFIGURATION_AUDIT_V1`` envelope over the frozen configuration document
    (``configuration/snapshot.py``)."""
    document = json.loads(snapshot.configuration_json)
    if not isinstance(document, dict):
        raise ValueError("the frozen configuration is not a JSON object")
    return _hash_envelope_bytes(HashingProfile.CONFIGURATION_AUDIT_V1, document)


def dataset_identity_bytes(
    descriptor: DatasetDescriptor, partitions: tuple[DatasetPartition, ...]
) -> bytes:
    """The bytes whose SHA-256 is the dataset ``content_hash``: the
    ``DATASET_METADATA_V1`` envelope over the material metadata of the descriptor
    and its ordered partitions (``datasets/hashing.py::dataset_metadata_hash``,
    whose exclusions are restated here because the payload builder is private)."""
    ordered = sorted(partitions, key=lambda partition: partition.ordinal)
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
            mode="json", exclude={"dataset_id", "partition_id", "relative_path"}
        )
        for partition in ordered
    ]
    return _hash_envelope_bytes(
        HashingProfile.DATASET_METADATA_V1,
        {"descriptor": descriptor_payload, "partitions": partition_payloads},
    )


def strategy_identity_bytes(version: StrategyVersion) -> bytes:
    """The bytes whose SHA-256 is the strategy ``content_hash``: the
    ``STRATEGY_VERSION_V1`` envelope over ``strategy_version_payload``."""
    return _hash_envelope_bytes(
        HashingProfile.STRATEGY_VERSION_V1,
        dict(strategy_version_payload(version.strategy_spec)),
    )


def _root_paths_of(paths: CommandPaths) -> CommandRootPaths:
    """Plan 4.1: the Stage 7 ``CommandPaths`` destructured into the domain-typed
    ``CommandRootPaths`` the finalization consumes."""
    command_root = Path(paths.command_root)
    request_path = Path(paths.request_path)
    if isinstance(paths.work_dir, str) and isinstance(paths.result_path, str):
        return CommandRootPaths(
            command_root=command_root,
            request_path=request_path,
            work_dir=Path(paths.work_dir),
            result_path=Path(paths.result_path),
        )
    assert isinstance(paths.output_path, str)
    return CommandRootPaths(
        command_root=command_root,
        request_path=request_path,
        output_path=Path(paths.output_path),
    )


def _rediscovered_roots(command_root: Path) -> CommandRootPaths | MISSING:  # type: ignore[valid-type]
    """The command root of a reopened flow, read back from the Stage 7 layout
    (``request.json``; ``runs/<run_id>/work`` for a ``RUN``, ``output.json``
    otherwise)."""
    if not command_root.is_dir():
        return MISSING
    request_path = command_root / _REQUEST_FILE_NAME
    runs = command_root / _RUNS_SEGMENT
    if runs.is_dir():
        run_dirs = sorted(child for child in runs.iterdir() if child.is_dir())
        if run_dirs:
            work_dir = run_dirs[0] / _WORK_SEGMENT
            return CommandRootPaths(
                command_root=command_root,
                request_path=request_path,
                work_dir=work_dir,
                result_path=work_dir / RESULT_MANIFEST_RELATIVE_PATH,
            )
    return CommandRootPaths(
        command_root=command_root,
        request_path=request_path,
        output_path=command_root / _OUTPUT_FILE_NAME,
    )


class FinalizingSupervisedFlow(SupervisedSqliteFlow):
    """Plan 7.1 (Task 8): the Stage 8 supervised flow with the Stage 9 composition.

    The roots: the supervision root doubles as the Stage 9 runtime root with
    ``staging/`` and ``quarantine/`` beside the ``inv_*`` command roots, the
    content-addressed store under the sibling ``artifacts/`` and the JSON Lines
    log under the sibling ``logs/``. ``conclude_and_finalize`` replaces the Stage
    8 ``conclude``: the production ``observe_candidates`` before the verdict for
    a ``RUN`` (empty observations for a ``VALIDATE``), ``semantic_outcome_or_replay``
    whose stored conclusion is passed through on replay, then ``conclude_command``
    over the destructured outcome and paths; an observation refusal goes through
    ``fail_run_for_refusal`` and the invocation's core evidence is still staged
    and finalized. ``describe`` adds ``conclude_describe``. ``recover`` runs the
    Stage 7 reconciliation before the artifact reconciliation.
    """

    def __init__(
        self,
        database: SqliteDatabase,
        config: ApplicationConfig,
        *,
        clock: FixedClock,
        supervision_root: Path,
    ) -> None:
        super().__init__(
            database, config, clock=clock, supervision_root=supervision_root
        )
        self._closed = False
        self.runtime_root = supervision_root
        self.staging_root = supervision_root / _STAGING_SEGMENT
        self.quarantine_root = supervision_root / _QUARANTINE_SEGMENT
        self.artifacts_root = supervision_root.parent / _ARTIFACTS_SEGMENT
        self.logs_root = supervision_root.parent / _LOGS_SEGMENT
        self.staging_root.mkdir(exist_ok=True)
        self.artifacts_root.mkdir(exist_ok=True)
        self.hasher = StreamingContentHasher()
        self.store: ArtifactStore = ok(
            ArtifactStore.open(
                self.staging_root,
                self.artifacts_root,
                self.quarantine_root,
                now_utc=clock.now_utc(),
                hasher=self.hasher,
            )
        )
        self.harness = ArtifactHarness(database)
        committed = len(self.harness.committed_audit_events())
        self.audit_ids = SequentialAuditIds(f"{_AUDIT_SEED}-{committed}")
        self.auditor = AuditFactRecorder(self.audit_ids, clock)
        self.registrar = ResultRegistrar(
            self.auditor, clock, transactions=self._root.begin
        )
        timeout = config.process.finalization_timeout_seconds
        self.validator = ProductionRecoveryValidator(
            unit_of_work=self._root,
            hasher=self.hasher,
            negotiated_versions=DEFAULT_NEGOTIATED,
            finalization_timeout_seconds=timeout,
            clock=clock,
            registrar=self.registrar,
        )
        self.conclusion_config = ConclusionConfig(
            store=self.store,
            hasher=self.hasher,
            auditor=self.auditor,
            finalization_timeout_seconds=timeout,
            registrar=self.registrar,
        )
        writer = ok(
            JsonLinesLogWriter.open(
                self.logs_root,
                retained_files=config.logging.retained_files,
                clock=clock,
            )
        )
        self.log = JsonLinesFinalizationLog(writer, clock)

    @classmethod
    def open(
        cls, tmp_path: Path, *, config: ApplicationConfig = FINALIZING_CONFIG
    ) -> FinalizingSupervisedFlow:
        """Migrate ``tmp_path / "db"`` and compose the finalizing flow over it.

        The supervision root is the short ``sv`` segment rather than the Stage 8
        ``supervision``: core staging spends 117 characters on the owner-hash,
        correlation and invocation directories below it, and under pytest's
        temporary directory the Stage 8 name pushes a staged leaf past the
        259-character file ceiling of a host without long-path support.
        """
        clock = FixedClock(INSTANT)
        directory = tmp_path / _DATABASE_SEGMENT
        directory.mkdir(exist_ok=True)
        supervision_root = tmp_path / _SUPERVISION_SEGMENT
        supervision_root.mkdir(exist_ok=True)
        return cls(
            open_test_database(directory, clock=clock),
            config,
            clock=clock,
            supervision_root=supervision_root,
        )

    @classmethod
    def reopen(
        cls, tmp_path: Path, *, config: ApplicationConfig = FINALIZING_CONFIG
    ) -> FinalizingSupervisedFlow:
        """The same file and roots through new objects only; the command roots a
        ``close(keep_command_roots=True)`` left are rediscovered on demand."""
        return cls.open(tmp_path, config=config)

    @staticmethod
    def scenario(name: str) -> Scenario:
        """One of the Stage 9 rows, by its ``Scenario.name``."""
        assert name in STAGE9_SUPERVISED_ROW_NAMES, name
        return _STAGE9_SCENARIO_BY_NAME[name]

    @property
    def unit_of_work(self) -> SqliteUnitOfWork:
        """The root the Stage 9 composition opens its transactions through."""
        return self._root

    def close(self, *, keep_command_roots: bool = False) -> None:
        """Close the log, then the Stage 8 close; idempotent."""
        if self._closed:
            return
        self._closed = True
        try:
            self.log.close()
        finally:
            super().close(keep_command_roots=keep_command_roots)

    def assert_no_child_survives(self) -> int:
        """28.3:2096: every identity a tee launched or recorded is not
        ``ALIVE_MATCHING``; returns how many identities were checked."""
        self._assert_nothing_launched_survives()
        return sum(len(tee.identities) + len(tee.descendants) for tee in self._tees)

    # -- composition -----------------------------------------------------------

    def finalizer(
        self, probe: FinalizationProbe | None = None
    ) -> CoreArtifactFinalizer:
        """The production finalizer over the production registrar; ``probe`` is
        per call, so a recovery never re-trips a crashing probe."""
        return CoreArtifactFinalizer(
            self._root.begin,
            self.clock,
            self.hasher,
            self.store,
            probe if probe is not None else NoProbe(),
            self.registrar,
            self.auditor,
            command_roots=self.command_roots,
            token_material=self.token_material,
            log=self.log,
        )

    def command_roots(self, invocation_id: str) -> CommandRootPaths | MISSING:  # type: ignore[valid-type]
        """The command root of an invocation this flow planned, or the one read
        back from the supervision root after a reopen."""
        paths = self._paths.get(invocation_id)
        if paths is not None:
            return _root_paths_of(paths)
        return _rediscovered_roots(self.supervision_root / invocation_id)

    def token_material(self, invocation_id: str) -> AttemptTokenMaterial | MISSING:  # type: ignore[valid-type]
        """The attempt token read from the surviving Stage 7 request envelope
        (``payload.attempt_token`` of an ``EngineRunRequest``); absent for a
        describe root, a closed root or an unreadable envelope. The material is
        the caller's frame's alone."""
        roots = self.command_roots(invocation_id)
        if not isinstance(roots, CommandRootPaths) or not roots.request_path.is_file():
            return MISSING
        try:
            envelope = AdapterCommandRequestEnvelope.model_validate_json(
                roots.request_path.read_bytes()
            )
        except (OSError, ValidationError, ValueError):
            return MISSING
        payload = envelope.payload
        if not isinstance(payload, EngineRunRequest):
            return MISSING
        return AttemptTokenMaterial(
            run_id=payload.run_id, attempt_token=payload.attempt_token
        )

    def raw_token(self, run_id: str) -> str:
        """The raw attempt token the flow holds for ``run_id``, for the positive
        control of the token scan alone."""
        return self._token_for(run_id)

    def _invoke(self, row: Scenario, run: EngineRunRecord | None) -> SupervisionOutcome:
        outcome = super()._invoke(row, run)
        self.log.project_trace(outcome.trace)
        return outcome

    def describe(self, row: Scenario) -> DescribeConclusion:
        """S-1, then plan 4.6: ``conclude_describe`` over the describe outcome."""
        described = super().describe(row)
        outcome = described.outcome
        invocation = outcome.command_result.invocation
        roots = self.command_roots(invocation.invocation_id)
        assert isinstance(roots, CommandRootPaths)
        parse = outcome.output_parse
        refs = ok(
            conclude_describe(
                outcome.command_result,
                parse if isinstance(parse, DescriptorParse) else MISSING,
                described.reconciliation,
                roots=roots,
                config=self.conclusion_config,
                unit_of_work=self._root,
                finalizer=self.finalizer(),
                clock=self.clock,
            )
        )
        return DescribeConclusion(
            outcome=described.outcome,
            reconciliation=described.reconciliation,
            observation=described.observation,
            owner_hash=described.owner_hash,
            evidence_refs=refs,
        )

    def conclude_and_finalize(
        self,
        row: Scenario,
        run: EngineRunRecord,
        outcome: SupervisionOutcome,
        *,
        probe: FinalizationProbe | None = None,
    ) -> CommandConclusion | None:
        """Plan 4.4 for an ``EXITED`` invocation: the production candidate
        observation before the verdict (a ``VALIDATE`` supplies none), the
        verdict through ``semantic_outcome_or_replay`` (a stored conclusion is
        passed through), then ``conclude_command`` over the destructured outcome
        and paths with the frame's token material. A core-won terminal returns
        ``None``; an observation refusal fails the run through
        ``fail_run_for_refusal`` and still finalizes the invocation's evidence."""
        invocation = outcome.command_result.invocation
        if invocation.state is not CommandInvocationState.EXITED:
            return None
        roots = self.command_roots(invocation.invocation_id)
        assert isinstance(roots, CommandRootPaths)
        token = AttemptTokenMaterial(
            run_id=run.run_id, attempt_token=self._token_for(run.run_id)
        )
        parse: Any = outcome.output_parse
        assert not isinstance(parse, DescriptorParse)
        finalizer = self.finalizer(probe)
        # B7-03: the stored revisions, re-read after the supervisor's last write.
        stored_run = self.fresh_run(run.run_id)
        stored_invocation = self.fresh_invocation(invocation.invocation_id)
        observations: tuple[CandidateObservation, ...] = ()
        if row.command is CommandKind.RUN:
            assert isinstance(roots.work_dir, Path)
            observed = observe_candidates(
                roots.work_dir,
                declared_candidate_paths(outcome.protocol_summary, parse),
                token,
                hasher=self.hasher,
                clock=self.clock,
            )
            if isinstance(observed, Failure):
                return self._conclude_refused(
                    observed, stored_run, outcome, roots, token, finalizer
                )
            observations = observed.value
        answered = ok(
            semantic_outcome_or_replay(
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
                unit_of_work=self._root,
                clock=self.clock,
            )
        )
        if isinstance(answered, CommandConclusion):
            return answered  # reading 24: the stored conclusion, passed through
        return ok(
            conclude_command(
                answered,
                outcome.command_result,
                parse,
                outcome.protocol_summary,
                observations,
                roots=roots,
                token=token,
                config=self.conclusion_config,
                unit_of_work=self._root,
                finalizer=finalizer,
                clock=self.clock,
            )
        )

    def _conclude_refused(
        self,
        refusal: Failure,
        stored_run: EngineRunRecord,
        outcome: SupervisionOutcome,
        roots: CommandRootPaths,
        token: AttemptTokenMaterial,
        finalizer: CoreArtifactFinalizer,
    ) -> CommandConclusion:
        """Plan 4.4 step 0: a refused observation fails the run through
        ``fail_run_for_refusal`` (the diagnostic recorded, ``RUN_FAILED`` audited,
        the root closed) and the invocation's stderr and protocol capture are
        still staged and finalized under the ``INVOCATION`` correlation."""
        invocation = outcome.command_result.invocation
        invocation_id = invocation.invocation_id
        ok(
            fail_run_for_refusal(
                refusal,
                run_id=stored_run.run_id,
                expected_run_revision=stored_run.revision,
                roots=roots,
                config=self.conclusion_config,
                unit_of_work=self._root,
                clock=self.clock,
            )
        )
        owner = RunArtifactOwner(
            owner_kind="RUN",
            experiment_id=stored_run.experiment_id,
            run_id=stored_run.run_id,
            invocation_id=invocation_id,
        )
        staged: list[CandidateArtifact] = []
        stderr = outcome.command_result.stderr
        if isinstance(stderr, StderrCapture):
            staged.append(
                ok(
                    stderr_evidence(
                        stderr,
                        owner,
                        invocation_id,
                        store=self.store,
                        unit_of_work=self._root,
                        auditor=self.auditor,
                        clock=self.clock,
                    )
                )
            )
        if outcome.command_result.accepted_events:
            staged.append(
                ok(
                    protocol_capture_evidence(
                        outcome.command_result.accepted_events,
                        owner,
                        invocation_id,
                        store=self.store,
                        unit_of_work=self._root,
                        clock=self.clock,
                    )
                )
            )
        evidence_refs: tuple[ArtifactRef, ...] = ()
        evidence_failure: Failure | MISSING = MISSING  # type: ignore[valid-type]
        if staged:
            finalized = finalize_evidence(
                staged,
                EvidenceCorrelation(kind="INVOCATION", invocation_id=invocation_id),
                finalizer=finalizer,
                token=token,
            )
            if isinstance(finalized, Failure):
                evidence_failure = finalized
            else:
                evidence_refs = tuple(
                    self.fresh_ref(mapping.artifact_id)
                    for mapping in finalized.value.candidate_to_artifact_refs
                )
        return CommandConclusion(
            run=self.fresh_run(stored_run.run_id),
            invocation=self.fresh_invocation(invocation_id),
            evidence_refs=evidence_refs,
            evidence_failure=evidence_failure,
        )

    def recover(self) -> RecoveryReports:
        """Plan 7.1: the Stage 7 ``reconcile()`` first, then
        ``reconcile_finalization`` over the flow's runtime root."""
        process = self.reconcile()
        artifacts = ok(
            reconcile_finalization(
                unit_of_work_factory=self._root.begin,
                store=self.store,
                hasher=self.hasher,
                registrar=self.registrar,
                recovery_validator=self.validator,
                auditor=self.auditor,
                clock=self.clock,
                runtime_root=self.runtime_root,
                command_roots=self.command_roots,
                token_material=self.token_material,
                log=self.log,
            )
        )
        return RecoveryReports(process=process, artifacts=artifacts)

    # -- the Stage 5 run and experiment writes the rows use -------------------

    def cancel_run(self, run_id: str) -> EngineRunRecord:
        """RC-1 and reading 23: the production run-cancel edge after ``EXITED`` --
        ``transition_run`` to ``CANCELLED`` with a recorded ``CANCELLATION``
        diagnostic naming the run's ``RUN`` invocation."""
        run = self.fresh_run(run_id)
        invocations = [
            invocation
            for invocation in self.harness.lifecycle().committed_command_invocations()
            if invocation.run_id == run_id
            and invocation.command_kind is CommandKind.RUN
        ]
        assert len(invocations) == 1, "the run has exactly one RUN invocation"
        diagnostic = sample_diagnostic(
            f"diag_{_uuid4_shaped(sha256_bytes(f'cancel:{run_id}'.encode()))}",
            error_code=_CANCELLATION_CODE,
            category=DiagnosticCategory.CANCELLATION,
            retriable=False,
            experiment_id=run.experiment_id,
            run_id=run_id,
            invocation_id=invocations[0].invocation_id,
            timestamp_utc=self.clock.now_utc(),
        )
        ok(self.recorder.record(diagnostic))
        return ok(
            transition_run(
                RunTransitionRequest(
                    schema_version="1.0.0",
                    run_id=run_id,
                    expected_revision=run.revision,
                    target_state=EngineRunState.CANCELLED,
                    reason_code=_FIXTURE_REASON,
                    primary_terminal_diagnostic_id=diagnostic.diagnostic_id,
                ),
                unit_of_work=self.counting,
                clock=self.clock,
            )
        )

    def cancel_experiment(self, experiment_id: str) -> ExperimentRecord:
        """The Stage 5 ``cancel_experiment`` over the current experiment row: it
        swaps the experiment to ``CANCELLED`` and reads no run (reading 23)."""
        experiment = self.fresh_experiment(experiment_id)
        return ok(
            cancel_experiment(
                CancelExperimentRequest(
                    schema_version="1.0.0",
                    experiment_id=experiment_id,
                    expected_revision=experiment.revision,
                    correlation_id=_CANCEL_CORRELATION,
                ),
                unit_of_work=self.counting,
                clock=self.clock,
            )
        )

    # -- authoritative durable readers -----------------------------------------

    def fresh_dataset(
        self, content_hash: str
    ) -> tuple[DatasetDescriptor, tuple[DatasetPartition, ...]]:
        """The dataset registered under ``content_hash`` and its partitions in
        ordinal order, read back from the authoritative registry through fresh
        sessions (never the fixture builders)."""
        descriptor = self._fresh(
            lambda opened: ok(opened.datasets.get_by_hash(content_hash))
        )
        partitions = self._fresh(
            lambda opened: ok(opened.datasets.list_partitions(descriptor.dataset_id))
        )
        return descriptor, partitions

    def fresh_strategy_version(self, content_hash: str) -> StrategyVersion:
        """The strategy version registered under ``content_hash``, read back from
        the authoritative registry through a fresh session."""
        return self._fresh(
            lambda opened: ok(opened.strategy_versions.get_by_hash(content_hash))
        )

    def fresh_runs(self) -> tuple[EngineRunRecord, ...]:
        return self.harness.lifecycle().committed_engine_runs()

    def fresh_candidates(self) -> tuple[CandidateArtifact, ...]:
        return self.harness.committed_candidates()

    def fresh_journal(self) -> tuple[FinalizationJournalEntry, ...]:
        return self.harness.committed_journal()

    def fresh_audit(self) -> tuple[AuditEvent, ...]:
        return self.harness.committed_audit_events()

    def fresh_ref(self, artifact_id: str) -> ArtifactRef:
        return self._fresh(lambda opened: ok(opened.artifact_refs.get(artifact_id)))

    def fresh_refs(self, run_id: str) -> tuple[ArtifactRef, ...]:
        """Every reference whose ``RUN`` owner names ``run_id`` (both of the
        attempt's invocations), sorted by identity."""
        return tuple(
            ref
            for ref in self.harness.committed_refs()
            if isinstance(ref.owner, RunArtifactOwner) and ref.owner.run_id == run_id
        )

    def fresh_links(self, run_id: str) -> tuple[RunArtifactLink, ...]:
        return tuple(
            link
            for link in self.harness.committed_run_artifacts()
            if link.run_id == run_id
        )

    def fresh_manifest(self, run_id: str) -> RunManifest | None:
        """The run's ``RunManifest`` decoded from its row, or ``None``."""
        facts = self._fresh(lambda opened: ok(opened.run_manifests.get(run_id)))
        if not isinstance(facts, RunManifestFacts):
            return None
        return RunManifest.model_validate_json(facts.manifest_json)

    def fresh_manifest_facts(self, run_id: str) -> RunManifestFacts:
        facts = self._fresh(lambda opened: ok(opened.run_manifests.get(run_id)))
        assert isinstance(facts, RunManifestFacts), "the run has no manifest row"
        return facts

    def fresh_sanitized_manifest(self, sanitized_hash: str) -> SanitizedManifestFacts:
        facts = self._fresh(
            lambda opened: ok(opened.sanitized_manifests.get(sanitized_hash))
        )
        assert isinstance(facts, SanitizedManifestFacts), "no sanitized row"
        return facts

    def fresh_validation_result(self, invocation_id: str) -> ValidationResultFacts:
        facts = self._fresh(
            lambda opened: ok(opened.validation_results.get(invocation_id))
        )
        assert isinstance(facts, ValidationResultFacts), "no validation row"
        return facts

    def _committed_diagnostics(self) -> tuple[Diagnostic, ...]:
        statement = select(DiagnosticRow).order_by(DiagnosticRow.diagnostic_id)
        return tuple(
            ok(decode_diagnostic(row, clock=self.clock))
            for row in self.harness._rows(statement)
        )

    def durable(self, run_id: str) -> DurableState:
        """Every Stage 9 table beside the run's row and its ``RUN`` invocation,
        the filesystem listing and the audit rows, through fresh sessions."""
        runs = [run for run in self.fresh_runs() if run.run_id == run_id]
        invocations = [
            invocation
            for invocation in self.harness.lifecycle().committed_command_invocations()
            if invocation.run_id == run_id
            and invocation.command_kind is CommandKind.RUN
        ]
        return DurableState(
            journal=self.fresh_journal(),
            candidates=self.fresh_candidates(),
            refs=self.harness.committed_refs(),
            run=runs[0] if runs else None,
            invocation=invocations[0] if invocations else None,
            run_manifests=self.harness.committed_run_manifests(),
            run_artifacts=self.harness.committed_run_artifacts(),
            audit_events=self.fresh_audit(),
            diagnostics=self._committed_diagnostics(),
            object_blobs=self.object_blobs(),
            staging_files=self.staging_files(),
            command_root_files=self.command_root_files(),
            quarantine_entries=self.quarantine_entries(),
        )

    # -- the filesystem ---------------------------------------------------------

    def object_blobs(self) -> tuple[str, ...]:
        """The content hashes present under ``objects/``, sorted."""
        return tuple(
            sorted(path.name for path in _files_under(self.store.objects_root))
        )

    def staging_files(self) -> tuple[str, ...]:
        return tuple(
            path.relative_to(self.staging_root).as_posix()
            for path in _files_under(self.staging_root)
        )

    def _command_root_dirs(self) -> tuple[Path, ...]:
        """Every ``inv_*`` directory under the supervision root, from disk."""
        return tuple(
            child
            for child in sorted(self.supervision_root.iterdir())
            if child.is_dir() and child.name.startswith(_COMMAND_ROOT_PREFIX)
        )

    def command_root_files(self) -> tuple[str, ...]:
        """Every file under a command root, as ``<invocation_id>/<relative>``."""
        files: list[str] = []
        for root in self._command_root_dirs():
            files.extend(
                f"{root.name}/{path.relative_to(root).as_posix()}"
                for path in _files_under(root)
            )
        return tuple(files)

    def quarantine_entries(self) -> tuple[QuarantineEntry, ...]:
        return self.store.quarantine_entries()

    # -- the raw-token scan -------------------------------------------------------

    def scan_for_token(
        self, token: str, *, extra_roots: Sequence[Path] = ()
    ) -> TokenScanReport:
        """The test-side exact-byte scan over every durable surface: the
        checkpointed database file, its ``-wal`` and ``-shm`` sidecars when
        present, every cell of every table (the ``*_json`` cells counted), the
        logs, artifacts, quarantine and staging roots, every ``inv_*`` command
        root on disk and every registered blob by its reference; ``extra_roots``
        admits the positive control's scratch root."""
        needle = token.encode("utf-8")
        if not needle:
            raise ValueError("token must not be empty")
        surfaces: dict[str, int] = {}
        hits: list[str] = []

        def scan_files(label: str, files: Sequence[Path]) -> None:
            surfaces[label] = surfaces.get(label, 0) + len(files)
            hits.extend(str(path) for path in files if token_scan(path, needle))

        # The checkpoint runs under asserted quiescence (ledger A7-01/B7-01) so
        # every committed frame is in the main file before it is read.
        self.database_sha256()
        database_path = self.database.path
        scan_files("database", (database_path,))
        for label, suffix in (("wal", "-wal"), ("shm", "-shm")):
            sidecar = Path(f"{database_path}{suffix}")
            scan_files(label, (sidecar,) if sidecar.is_file() else ())
        surfaces["json_columns"] = self._scan_cells(token, needle, hits)
        scan_files("logs", _files_under(self.logs_root))
        scan_files("artifacts", _files_under(self.artifacts_root))
        scan_files("quarantine", _files_under(self.quarantine_root))
        scan_files("staging", _files_under(self.staging_root))
        surfaces["command_roots"] = 0
        for root in self._command_root_dirs():
            scan_files("command_roots", _files_under(root))
        blobs: list[Path] = []
        for ref in self.harness.committed_refs():
            blob = self.store.finalized_path_for(ref.content_hash)
            assert blob.is_file(), f"registered blob of {ref.artifact_id} is missing"
            blobs.append(blob)
        scan_files("blobs", blobs)
        for extra in extra_roots:
            scan_files(f"extra:{extra.name}", _files_under(extra))
        return TokenScanReport(surfaces=surfaces, hits=tuple(hits))

    def _scan_cells(self, token: str, needle: bytes, hits: list[str]) -> int:
        """Every cell of every user table through the independent stdlib
        connection; returns how many ``*_json`` cells were scanned."""
        json_cells = 0
        connection = raw_connection(self.database.path)
        try:
            tables = [str(row[0]) for row in connection.execute(_USER_TABLES_SQL)]
            for table in tables:
                assert table.replace("_", "").isalnum(), table
                # The identifier comes from sqlite_master and was just checked;
                # SQLite admits no bound parameter in place of a table name.
                cursor = connection.execute(f'SELECT * FROM "{table}"')  # noqa: S608
                columns = [str(item[0]) for item in cursor.description]
                for row in cursor:
                    for column, cell in zip(columns, row, strict=True):
                        if column.endswith(_JSON_COLUMN_SUFFIX):
                            json_cells += 1
                        if (isinstance(cell, str) and token in cell) or (
                            isinstance(cell, bytes) and needle in cell
                        ):
                            hits.append(f"{table}.{column}")
        finally:
            connection.close()
        return json_cells
