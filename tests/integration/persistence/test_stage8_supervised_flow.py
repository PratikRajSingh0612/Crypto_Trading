"""The eight supervised rows of plan 7.1.2 over the SQLite test database (Task 7).

``SupervisedSqliteFlow`` drives the selected Stage 6 scenario rows through the
production ``WindowsProcessSupervisor`` with every persistence-dependent component
bound to one migrated SQLite file: ``Stage5InvocationLifecycle`` over
``SqliteUnitOfWork`` under ``CountingUnitOfWork``, ``SqliteDiagnosticRecorder``,
the Task 3/4 writers and repositories and, for the reopen case,
``SqliteReconciliationSource``. Every durable assertion here is a fresh read of
the file after the writer's last operation returned; a returned
``SupervisionOutcome`` is never counted as persistence proof. The memory-bound
negative control of S-3 reads the same file through an independent stdlib
connection and hashes the checkpointed main file before and after the row.

Test-local readings, declared rather than inferred silently:

- ``supervised_sqlite_flow`` is this module's fixture (ledger A7-04/B7-06); no
  ``conftest.py`` is created under ``tests/integration/persistence`` (the Task 5
  mypy-identity reading).
- Row 26 (S-7) is asserted in the two forms the committed Stage 7 contract
  admits after the row-26 correction: a RUNNING-origin timeout records
  ``PROCESS.RUN_TIMED_OUT`` with ``process_created`` true and a native exit from
  enrichment; a pre-handoff timeout records ``PROCESS.START_TIMED_OUT`` with
  ``process_created`` false, no native exit and a removed command root. Neither
  form requires a request file after the supervisor's cleanup.
- The B7-02 boundary review is a positive, per-module import pin: every
  ``(module, name)`` pair each Task 7 module imports is enumerated here, keyed on
  the plan's "Interfaces consumed"; the shared ``harness.py`` is held to the
  denylist alone. Synthetic sources prove the scanner flags every forbidden form.
"""

from __future__ import annotations

import ast
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Final

import pytest

from contract.scenarios import Scenario
from crypto_lab.adapters.diagnostics import PROCESS_START_TIMED_OUT
from crypto_lab.adapters.reconciliation import SemanticReconciliation
from crypto_lab.adapters.vocabulary import ReconciliationVerdict
from crypto_lab.artifacts.ownership import AdapterArtifactOwner
from crypto_lab.configuration.models import ApplicationConfig
from crypto_lab.configuration.snapshot import snapshot_configuration
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.engine_run import SUCCESS_ENGINE_RUN_STATES
from crypto_lab.domain.lifecycle import (
    TERMINAL_ENGINE_RUN_STATES,
    CommandInvocationState,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.persistence.database import ConsistencyReport
from doubles.experiments import AVAIL_A
from persistence_support.supervised import SupervisedSqliteFlow

_C: Final = CommandInvocationState
_E: Final = ExperimentState
_R: Final = EngineRunState
_V: Final = ReconciliationVerdict
_PROCESS_TIMEOUT_ROW: Final = 26
#: ``create_attempt`` bumps the queued experiment (2) to ``RUNNING`` at 3; no run
#: edge, semantic outcome or lifecycle write bumps it afterwards.
_RUNNING_AFTER_ATTEMPT: Final = (_E.RUNNING, 3)

_SUPERVISED_MODULE: Final = "tests/persistence_support/supervised.py"
_HARNESS_MODULE: Final = "tests/persistence_support/harness.py"
_DURABLE_TEST_MODULE: Final = (
    "tests/integration/persistence/test_stage8_durable_flow.py"
)
_SUPERVISED_TEST_MODULE: Final = (
    "tests/integration/persistence/test_stage8_supervised_flow.py"
)

#: B7-02: the names no Task 7 module may import or reference, the module prefix
#: no Task 7 module may name, the two sibling-only Stage 7 modules, the bare
#: test-package imports and the one attribute of the in-memory harness.
_FORBIDDEN_NAMES: Final = frozenset(
    {
        "OfflineCommandHarness",
        "ProductionSupervision",
        "SeedingDiagnosticRecorder",
        "build_harness",
    }
)
_FORBIDDEN_NAME_PREFIX: Final = "InMemory"
_FORBIDDEN_MODULES: Final = frozenset({"supervised_strategy", "supervision_scenarios"})
_BARE_TEST_PACKAGES: Final = frozenset({"contract", "doubles"})
_FORBIDDEN_ATTRIBUTE: Final = "store"


def _pairs(module: str, *names: str) -> frozenset[tuple[str, str]]:
    """The ``(module, name)`` pairs of one import statement; a plain import is
    ``(module, "")``."""
    return frozenset((module, name) for name in (names or ("",)))


#: B7-02: the exact ``(module, name)`` pairs each Task 7 module imports, keyed
#: on the binding table of plan 7.1.2 and the Task 7 "Interfaces consumed"
#: paragraph. ``contract.harness`` supplies exactly four constants (A7-03);
#: ``contract.scenarios`` the table and its row type; ``doubles.supervision`` the
#: fake catalogue, the supervisor builder, the tee, the recording observer and the
#: monotonic clock; ``doubles.experiments`` the canonical identities and clocks;
#: the production modules are imported from ``crypto_lab.*`` directly.
_SUPERVISED_IMPORTS: Final[frozenset[tuple[str, str]]] = frozenset().union(
    _pairs("__future__", "annotations"),
    _pairs("asyncio"),
    _pairs("shutil"),
    _pairs("sys"),
    _pairs("collections.abc", "Callable"),
    _pairs("dataclasses", "dataclass"),
    _pairs("pathlib", "Path"),
    _pairs("typing", "Any", "Final"),
    _pairs("pydantic.experimental.missing_sentinel", "MISSING"),
    _pairs("sqlalchemy.pool", "QueuePool"),
    _pairs(
        "contract.harness",
        "DEFAULT_NEGOTIATED",
        "FAKE_OPERATING_SYSTEM",
        "FAKE_RUNTIME_VERSION",
        "OBSERVATION_VALIDITY",
    ),
    _pairs("contract.scenarios", "SCENARIOS", "Scenario"),
    _pairs("crypto_lab.adapters.catalog", "AdapterCatalogEntry"),
    _pairs("crypto_lab.adapters.commands", "AdapterCommand"),
    _pairs(
        "crypto_lab.adapters.envelopes",
        "DescribeRequestPayload",
        "request_hash_of",
        "request_material_hash",
    ),
    _pairs("crypto_lab.adapters.events", "ProtocolEventSummary", "RunEvent"),
    _pairs(
        "crypto_lab.adapters.limits",
        "MAX_DESCRIPTOR_OUTPUT_BYTES",
        "MAX_VALIDATION_RESULT_BYTES",
        "PROTOCOL_LIMITS_DEFAULT",
    ),
    _pairs(
        "crypto_lab.adapters.manifests",
        "AdapterResultManifest",
        "ManifestParse",
        "parse_result_manifest",
        "parse_validation_result",
    ),
    _pairs(
        "crypto_lab.adapters.negotiation",
        "CORE_PROTOCOL_SUPPORT",
        "describe_availability_observation",
        "parse_bootstrap_descriptor",
    ),
    _pairs(
        "crypto_lab.adapters.reconciliation",
        "CandidateObservation",
        "SemanticReconciliation",
        "reconcile_describe",
    ),
    _pairs("crypto_lab.adapters.sanitization", "token_present"),
    _pairs(
        "crypto_lab.artifacts.ownership", "AdapterArtifactOwner", "ArtifactOwnerRef"
    ),
    _pairs("crypto_lab.configuration.models", "ApplicationConfig"),
    _pairs("crypto_lab.configuration.snapshot", "ConfigSnapshot"),
    _pairs("crypto_lab.datasets.models", "DatasetDescriptor"),
    _pairs(
        "crypto_lab.domain.command_invocation",
        "CommandInvocationRecord",
        "ProcessIdentity",
    ),
    _pairs("crypto_lab.domain.descriptors", "RuntimeAvailabilityObservation"),
    _pairs("crypto_lab.domain.diagnostics", "Diagnostic"),
    _pairs("crypto_lab.domain.engine_run", "AttemptTokenMaterial", "EngineRunRecord"),
    _pairs("crypto_lab.domain.experiment", "ExperimentRecord"),
    _pairs("crypto_lab.domain.hashing", "sha256_bytes"),
    _pairs(
        "crypto_lab.domain.lifecycle",
        "CommandInvocationState",
        "CommandKind",
        "EngineRunState",
    ),
    _pairs(
        "crypto_lab.experiments.invocation_service",
        "create_invocation",
        "enrich_invocation",
    ),
    _pairs(
        "crypto_lab.experiments.requests",
        "AttemptCreationRequest",
        "InvocationCreationRequest",
        "InvocationEnrichmentRequest",
        "RunTransitionRequest",
        "SemanticOutcomeRequest",
    ),
    _pairs("crypto_lab.experiments.run_service", "create_attempt", "transition_run"),
    _pairs(
        "crypto_lab.experiments.semantic_outcome",
        "SemanticOutcome",
        "apply_command_semantic_outcome",
    ),
    _pairs(
        "crypto_lab.experiments.supervision_lifecycle",
        "RequestMaterial",
        "Stage5InvocationLifecycle",
    ),
    _pairs("crypto_lab.persistence.database", "ConsistencyReport", "SqliteDatabase"),
    _pairs(
        "crypto_lab.persistence.reconciliation_source", "SqliteReconciliationSource"
    ),
    _pairs("crypto_lab.persistence.registries", "SqliteDiagnosticRecorder"),
    _pairs(
        "crypto_lab.persistence.unit_of_work", "SqliteTransaction", "SqliteUnitOfWork"
    ),
    _pairs(
        "crypto_lab.process_supervision.cancellation", "ThreadSafeCancellationToken"
    ),
    _pairs(
        "crypto_lab.process_supervision.models",
        "FORCED_TERMINATION_EXIT_CODE",
        "ProcessPresence",
        "ReconciliationReport",
        "SupervisionOutcome",
        "SupervisionTraceEntry",
        "SupervisionTraceKind",
    ),
    _pairs("crypto_lab.process_supervision.reconciliation", "reconcile_invocations"),
    _pairs(
        "crypto_lab.process_supervision.roots",
        "CommandPaths",
        "PathPreflight",
        "plan_command_paths",
    ),
    _pairs(
        "crypto_lab.process_supervision.windows_process", "WindowsProcessController"
    ),
    _pairs("crypto_lab.strategy.versioning", "StrategyVersion"),
    _pairs(
        "doubles.experiments",
        "AVAIL_A",
        "INSTANT",
        "SLOT_A",
        "FixedClock",
        "SequentialIdentitySource",
    ),
    _pairs(
        "doubles.supervision",
        "SCRIPTED_SUPERVISOR_INSTANCE_ID",
        "RealtimeMonotonicClock",
        "RecordingObserver",
        "TeeController",
        "build_supervisor",
        "supervised_catalog_entry_for",
    ),
    _pairs("persistence_support.fixtures", "supervised_draft"),
    _pairs(
        "persistence_support.harness",
        "REASON",
        "CountingUnitOfWork",
        "commit",
        "engine_of",
        "file_sha256",
        "fresh_read",
        "ok",
        "open_test_database",
        "queue_through_freeze",
        "raw_connection",
        "run_states_of",
        "sample_dataset_with_partitions",
        "sample_strategy_version",
    ),
)
_DURABLE_TEST_IMPORTS: Final[frozenset[tuple[str, str]]] = frozenset().union(
    _pairs("__future__", "annotations"),
    _pairs("datetime", "timedelta"),
    _pairs("pathlib", "Path"),
    _pairs("typing", "Final"),
    _pairs("crypto_lab.configuration.models", "ApplicationConfig"),
    _pairs("crypto_lab.configuration.snapshot", "snapshot_configuration"),
    _pairs(
        "crypto_lab.domain.aggregation",
        "REASON_SLOT_FAILED",
        "AggregationVerdict",
        "SlotRetryStatus",
    ),
    _pairs("crypto_lab.domain.engine_run", "SUCCESS_ENGINE_RUN_STATES"),
    _pairs("crypto_lab.domain.lifecycle", "EngineRunState", "ExperimentState"),
    _pairs(
        "crypto_lab.domain.retry",
        "RetryDecisionOutcome",
        "RetryDenialReason",
        "RetryGate",
        "recorded_denial_reason",
    ),
    _pairs("crypto_lab.experiments.diagnostics", "RETRY_NOT_BEFORE_NOT_REACHED"),
    _pairs("doubles.experiments", "SLOT_A", "SLOT_B"),
    _pairs("persistence_support.fixtures", "retrying_config"),
    _pairs("persistence_support.harness", "DurableFlow", "code", "ok"),
)
_SUPERVISED_TEST_IMPORTS: Final[frozenset[tuple[str, str]]] = frozenset().union(
    _pairs("__future__", "annotations"),
    _pairs("ast"),
    _pairs("os"),
    _pairs("collections.abc", "Iterator"),
    _pairs("pathlib", "Path"),
    _pairs("typing", "Final"),
    _pairs("pytest"),
    _pairs("contract.scenarios", "Scenario"),
    _pairs("crypto_lab.adapters.diagnostics", "PROCESS_START_TIMED_OUT"),
    _pairs("crypto_lab.adapters.reconciliation", "SemanticReconciliation"),
    _pairs("crypto_lab.adapters.vocabulary", "ReconciliationVerdict"),
    _pairs("crypto_lab.artifacts.ownership", "AdapterArtifactOwner"),
    _pairs("crypto_lab.configuration.models", "ApplicationConfig"),
    _pairs("crypto_lab.configuration.snapshot", "snapshot_configuration"),
    _pairs("crypto_lab.domain.command_invocation", "CommandInvocationRecord"),
    _pairs("crypto_lab.domain.engine_run", "SUCCESS_ENGINE_RUN_STATES"),
    _pairs(
        "crypto_lab.domain.lifecycle",
        "TERMINAL_ENGINE_RUN_STATES",
        "CommandInvocationState",
        "EngineRunState",
        "ExperimentState",
    ),
    _pairs("crypto_lab.persistence.database", "ConsistencyReport"),
    _pairs("doubles.experiments", "AVAIL_A"),
    _pairs("persistence_support.supervised", "SupervisedSqliteFlow"),
)
_ALLOWED_IMPORTS: Final[dict[str, frozenset[tuple[str, str]]]] = {
    _SUPERVISED_MODULE: _SUPERVISED_IMPORTS,
    _DURABLE_TEST_MODULE: _DURABLE_TEST_IMPORTS,
    _SUPERVISED_TEST_MODULE: _SUPERVISED_TEST_IMPORTS,
}

#: Synthetic sources the boundary scanner must flag, with the violation word.
_NEGATIVE_CONTROLS: Final[tuple[tuple[str, str], ...]] = (
    ("import contract\n", "bare import"),
    ("import doubles.experiments\n", "bare import"),
    ("from doubles.experiments import InMemoryBackingStore\n", "forbidden name"),
    ("from doubles.experiments import InMemoryUnitOfWork\n", "forbidden name"),
    ("from doubles.supervision import SeedingDiagnosticRecorder\n", "forbidden name"),
    (
        "from doubles.supervision import InMemoryReconciliationSource\n",
        "forbidden name",
    ),
    ("from contract.harness import OfflineCommandHarness\n", "forbidden name"),
    ("from contract.harness import build_harness\n", "forbidden name"),
    ("from supervised_strategy import ProductionSupervision\n", "forbidden module"),
    ("import supervision_scenarios\n", "forbidden module"),
    ("def f(flow):\n    return flow.store\n", "store attribute"),
    (
        "from contract.harness import CommandPlan\n"
        "class Flow(CommandPlan):\n    pass\n",
        "derives from a contract class",
    ),
    ("import doubles.experiments as e\nx = e.InMemoryBackingStore\n", "bare import"),
    ("from doubles import experiments as e\nx = e.InMemoryBackingStore\n", "forbidden"),
)


# --------------------------------------------------------------------------
# The fixture (A7-04 / B7-06: owned here)
# --------------------------------------------------------------------------


@pytest.fixture
def supervised_sqlite_flow(tmp_path: Path) -> Iterator[SupervisedSqliteFlow]:
    """One composition over one migrated database; closed in teardown, which
    terminates and awaits every launched child (the Stage 7 discipline)."""
    flow = SupervisedSqliteFlow.open(tmp_path, config=ApplicationConfig())
    try:
        yield flow
    finally:
        flow.close()


def _expected_core_won_primary(
    flow: SupervisedSqliteFlow, row: Scenario, invocation: CommandInvocationRecord
) -> str:
    """Stage 7 plan 9.4 after the row-26 correction: a row-26 terminal that never
    reached the RUNNING handoff carries ``PROCESS.START_TIMED_OUT``, no committed
    process-start facts and no native exit, and the supervisor removed its command
    root (``lstat`` fails with ``FileNotFoundError``; any other ``OSError``
    propagates, so "inaccessible" never passes) while the supervision root above
    it survives; every other core-won terminal carries the row's primary with the
    killed child's exit recorded by enrichment. Neither form requires a request
    file after the supervisor's cleanup."""
    if row.row == _PROCESS_TIMEOUT_ROW and invocation.process_created is False:
        assert not isinstance(invocation.native_exit_value, int)
        root = flow.command_root_of(invocation.invocation_id)
        try:
            os.lstat(root)
        except FileNotFoundError:
            absent = True
        else:
            absent = False
        assert absent, "the command root of a pre-handoff timeout was retained"
        assert root.parent.is_dir()
        return PROCESS_START_TIMED_OUT
    assert invocation.process_created is True
    assert isinstance(invocation.native_exit_value, int)
    assert row.primary_code is not None
    return row.primary_code


# --------------------------------------------------------------------------
# S-1, S-2, S-4, S-5: the storage obligations of plan 7.1.2
# --------------------------------------------------------------------------


def test_a_conformant_describe_persists_its_observation_and_owner_row(
    supervised_sqlite_flow: SupervisedSqliteFlow,
) -> None:
    flow = supervised_sqlite_flow
    row = flow.scenario("row01-conformant-describe")
    described = flow.describe(row)  # S-1 mints AVAIL_A
    assert flow.max_open_during_child == 0
    invocation_id = described.outcome.command_result.invocation.invocation_id
    invocation = flow.fresh_invocation(invocation_id)
    assert (invocation.state, invocation.native_exit_value) == (_C.EXITED, 0)
    assert not isinstance(invocation.run_id, str)  # a describe has no run facts
    assert described.reconciliation.verdict is _V.DESCRIBED
    observation = flow.fresh_observation(AVAIL_A)
    assert observation == described.observation
    assert (observation.available, observation.adapter_name) == (True, row.adapter_name)
    owner = flow.fresh_owner(described.owner_hash)
    assert isinstance(owner, AdapterArtifactOwner)
    assert (owner.owner_kind, owner.adapter_name) == ("ADAPTER", row.adapter_name)
    assert flow.independent_counts(invocation_id) == (1, 0)
    assert flow.consistency_report().dangling_diagnostic_references == 0
    assert flow.run_states() == frozenset()


def test_a_conformant_validate_row_reaches_ready_against_the_stored_observation(
    supervised_sqlite_flow: SupervisedSqliteFlow,
) -> None:
    flow = supervised_sqlite_flow
    flow.describe(flow.scenario("row01-conformant-describe"))
    row = flow.scenario("row02-conformant-validate")  # S-2
    run = flow.prepare_run(row)
    assert run.state is _R.VALIDATING  # A7-02: a VALIDATE row stops before READY
    outcome = flow.invoke(row, run)
    assert flow.max_open_during_child == 0
    semantic = flow.conclude(row, run, outcome)
    assert semantic is not None
    assert isinstance(semantic.reconciliation, SemanticReconciliation)
    assert semantic.reconciliation.verdict is _V.VALIDATED_READY
    invocation_id = outcome.command_result.invocation.invocation_id
    invocation = flow.fresh_invocation(invocation_id)
    assert (invocation.state, invocation.native_exit_value) == (_C.EXITED, 0)
    stored = flow.fresh_run(run.run_id)
    # The foreign key to S-1's observation row held.
    assert (stored.state, stored.availability_observation_id) == (_R.READY, AVAIL_A)
    events = flow.fresh_events(invocation_id)
    assert len(events) == row.accepted_events == 2
    assert [event.sequence for event in events] == sorted(e.sequence for e in events)
    assert events == outcome.command_result.accepted_events
    assert flow.independent_counts(invocation_id) == (1, 2)
    experiment = flow.fresh_experiment(stored.experiment_id)
    assert (experiment.state, experiment.revision) == _RUNNING_AFTER_ATTEMPT
    assert flow.frozen_snapshot(stored.experiment_id) == snapshot_configuration(
        flow.config
    )
    assert flow.token_absent_everywhere(run.run_id)
    assert flow.consistency_report().dangling_diagnostic_references == 0


@pytest.mark.parametrize(
    ("name", "run_state"),
    [
        ("row05-unsupported-capability-validate", _R.NOT_APPLICABLE),  # S-4
        ("row28-exit-40-run", _R.FAILED),  # S-5
    ],
)
def test_semantic_terminals_resolve_their_primary_once_the_caller_records_it(
    supervised_sqlite_flow: SupervisedSqliteFlow,
    name: str,
    run_state: EngineRunState,
) -> None:
    flow = supervised_sqlite_flow
    flow.describe(flow.scenario("row01-conformant-describe"))
    row = flow.scenario(name)
    run = flow.prepare_run(row)
    outcome = flow.invoke(row, run)  # the real supervisor; exit 20 or 40
    assert flow.max_open_during_child == 0
    semantic = flow.conclude(row, run, outcome)  # records the reconciliation's rows
    assert semantic is not None
    assert isinstance(semantic.reconciliation, SemanticReconciliation)
    assert semantic.reconciliation.verdict is row.verdict
    invocation_id = outcome.command_result.invocation.invocation_id
    invocation = flow.fresh_invocation(invocation_id)
    assert (invocation.state, invocation.native_exit_value) == (
        _C.EXITED,
        row.native_exit,
    )
    stored = flow.fresh_run(run.run_id)
    assert stored.state is run_state
    primary = flow.fresh_diagnostic(stored.primary_terminal_diagnostic_id)
    assert primary.error_code == row.primary_code
    assert (primary.run_id, primary.invocation_id) == (run.run_id, invocation_id)
    events = flow.fresh_events(invocation_id)
    if row.accepted_events is not None:
        assert len(events) == row.accepted_events
    # The independent connection agrees with the fresh session on the same file.
    assert flow.independent_counts(invocation_id) == (1, len(events))
    assert flow.consistency_report().dangling_diagnostic_references == 0
    assert flow.token_absent_everywhere(run.run_id)


# --------------------------------------------------------------------------
# S-3, S-6, S-7, S-8: the plan's Step 1 tests
# --------------------------------------------------------------------------


def test_a_conformant_run_row_persists_through_the_supervisor(
    supervised_sqlite_flow: SupervisedSqliteFlow,
) -> None:
    flow = supervised_sqlite_flow
    flow.describe(flow.scenario("row01-conformant-describe"))  # S-1 mints AVAIL_A
    row = flow.scenario("row03-conformant-run")  # S-3
    run = flow.prepare_run(row)  # registries, experiment, freeze, queue, READY
    before = flow.database_sha256()
    outcome = flow.invoke(row, run)  # the production supervisor over SQLite
    assert flow.max_open_during_child == 0
    semantic = flow.conclude(row, run, outcome)  # parse + semantic outcome
    assert semantic is not None
    invocation_id = outcome.command_result.invocation.invocation_id
    # Fresh session opened after the writer's last operation returned.
    invocation = flow.fresh_invocation(invocation_id)
    assert (invocation.state, invocation.native_exit_value) == (_C.EXITED, 0)
    stored = flow.fresh_run(run.run_id)
    assert stored.state is _R.RUNNING  # eligible, not final
    experiment = flow.fresh_experiment(stored.experiment_id)
    assert (experiment.state, experiment.revision) == _RUNNING_AFTER_ATTEMPT
    events = flow.fresh_events(invocation_id)
    assert len(events) == row.accepted_events == 5
    assert [event.sequence for event in events] == sorted(e.sequence for e in events)
    assert events == outcome.command_result.accepted_events
    assert flow.consistency_report().dangling_diagnostic_references == 0
    # Memory-bound negative control: an independent stdlib connection on the
    # same file sees the rows, and the file's bytes changed.
    assert flow.independent_counts(invocation_id) == (1, 5)
    assert flow.database_sha256() != before
    assert flow.token_absent_everywhere(run.run_id)
    assert (flow.max_open, flow.open_now) == (1, 0)


@pytest.mark.parametrize(
    ("name", "invocation_state", "run_state"),
    [
        ("row27-cancellation-run", _C.CANCELLED, _R.CANCELLED),  # S-6
        ("row26-process-timeout-run", _C.TIMED_OUT, _R.TIMED_OUT),  # S-7
    ],
)
def test_core_won_terminals_are_recorded_by_the_sqlite_lifecycle(
    supervised_sqlite_flow: SupervisedSqliteFlow,
    name: str,
    invocation_state: CommandInvocationState,
    run_state: EngineRunState,
) -> None:
    flow = supervised_sqlite_flow
    flow.describe(flow.scenario("row01-conformant-describe"))
    row = flow.scenario(name)
    run = flow.prepare_run(row)
    outcome = flow.invoke(row, run)  # no epilogue: a core-won terminal
    assert flow.max_open_during_child == 0
    assert flow.conclude(row, run, outcome) is None
    invocation_id = outcome.command_result.invocation.invocation_id
    invocation = flow.fresh_invocation(invocation_id)
    assert (invocation.state, invocation.cleanup_complete) == (invocation_state, True)
    stored_run = flow.fresh_run(run.run_id)
    assert stored_run.state is run_state
    primary = flow.fresh_diagnostic(stored_run.primary_terminal_diagnostic_id)
    assert primary.error_code == _expected_core_won_primary(flow, row, invocation)
    assert primary.diagnostic_id == invocation.primary_diagnostic_id
    events = flow.fresh_events(invocation_id)
    assert flow.independent_counts(invocation_id) == (1, len(events))
    report = flow.consistency_report()
    assert (report.dangling_diagnostic_references, report.causal_edge_mismatches) == (
        0,
        0,
    )
    assert flow.token_absent_everywhere(run.run_id)


def test_the_reopened_database_holds_every_supervised_row(tmp_path: Path) -> None:
    flow = SupervisedSqliteFlow.open(tmp_path, config=ApplicationConfig())
    ids: dict[str, str] = {}
    invocations: dict[str, str] = {}
    try:
        flow.describe(flow.scenario("row01-conformant-describe"))
        for name in (
            "row02-conformant-validate",
            "row03-conformant-run",
            "row05-unsupported-capability-validate",
            "row28-exit-40-run",
            "row27-cancellation-run",
            "row26-process-timeout-run",
        ):
            row = flow.scenario(name)
            run = flow.prepare_run(row)
            outcome = flow.invoke(row, run)
            flow.conclude(row, run, outcome)
            ids[name] = run.run_id
            invocations[name] = outcome.command_result.invocation.invocation_id
        assert (flow.max_open, flow.open_now) == (1, 0)
    finally:
        flow.close()  # disposes the engine and drops every application object
    reopened = SupervisedSqliteFlow.reopen(tmp_path)  # S-8: new objects, same file
    try:
        expected = {
            "row02-conformant-validate": _R.READY,
            "row03-conformant-run": _R.RUNNING,
            "row05-unsupported-capability-validate": _R.NOT_APPLICABLE,
            "row28-exit-40-run": _R.FAILED,
            "row27-cancellation-run": _R.CANCELLED,
            "row26-process-timeout-run": _R.TIMED_OUT,
        }
        assert {n: reopened.fresh_run(r).state for n, r in ids.items()} == expected
        assert reopened.fresh_observation(AVAIL_A).available is True
        # Every row's invocation facts, event ledger and primary re-read from the
        # reopened file with new objects (the S-8 row of plan 7.1.2).
        for name, invocation_id in invocations.items():
            row = reopened.scenario(name)
            invocation = reopened.fresh_invocation(invocation_id)
            assert (invocation.state, invocation.cleanup_complete) == (
                row.invocation_state,
                True,
            )
            if row.accepted_events is not None:
                assert len(reopened.fresh_events(invocation_id)) == row.accepted_events
            stored_run = reopened.fresh_run(ids[name])
            if stored_run.state in TERMINAL_ENGINE_RUN_STATES:
                primary = reopened.fresh_diagnostic(
                    stored_run.primary_terminal_diagnostic_id
                )
                assert primary.run_id == stored_run.run_id
        report = reopened.consistency_report()
        assert report == ConsistencyReport(*([0] * 8))  # all eight counts zero
        assert reopened.reconcile().entries == ()  # nothing left to reconcile
        assert reopened.run_states().isdisjoint(SUCCESS_ENGINE_RUN_STATES)
        assert reopened.quick_check() == "ok"
    finally:
        reopened.close()


# --------------------------------------------------------------------------
# B7-02: the positive per-module import pin and its negative controls
# --------------------------------------------------------------------------


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _import_pairs(tree: ast.AST) -> frozenset[tuple[str, str]]:
    """Every ``(module, name)`` a module imports; a plain import is ``(x, "")``."""
    pairs: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            pairs.update((alias.name, "") for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative imports are not used"
            module = node.module or ""
            pairs.update((module, alias.name) for alias in node.names)
    return frozenset(pairs)


def _forbidden_name(name: str) -> bool:
    return name in _FORBIDDEN_NAMES or name.startswith(_FORBIDDEN_NAME_PREFIX)


def _boundary_violations(tree: ast.AST, label: str) -> list[str]:
    """Plan 7.1.2 and B7-02: the forms no Task 7 module may contain."""
    violations: list[str] = []
    contract_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in _BARE_TEST_PACKAGES:
                    violations.append(
                        f"{label}:{node.lineno}: bare import {alias.name}"
                    )
                if root in _FORBIDDEN_MODULES:
                    violations.append(
                        f"{label}:{node.lineno}: forbidden module {alias.name}"
                    )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            root = module.split(".")[0]
            if root in _FORBIDDEN_MODULES:
                violations.append(f"{label}:{node.lineno}: forbidden module {module}")
            for alias in node.names:
                if module in _BARE_TEST_PACKAGES:
                    violations.append(
                        f"{label}:{node.lineno}: bare import {module}.{alias.name}"
                    )
                if _forbidden_name(alias.name):
                    violations.append(
                        f"{label}:{node.lineno}: forbidden name {alias.name}"
                    )
                if root == "contract":
                    contract_names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Attribute):
            if node.attr == _FORBIDDEN_ATTRIBUTE:
                violations.append(f"{label}:{node.lineno}: store attribute access")
            if _forbidden_name(node.attr):
                violations.append(f"{label}:{node.lineno}: forbidden name {node.attr}")
        elif isinstance(node, ast.Name) and _forbidden_name(node.id):
            violations.append(f"{label}:{node.lineno}: forbidden name {node.id}")
        elif isinstance(node, ast.ClassDef):
            for base in node.bases:
                base_name = base.id if isinstance(base, ast.Name) else None
                if base_name in contract_names:
                    violations.append(
                        f"{label}:{node.lineno}: {node.name} derives from a contract "
                        f"class {base_name}"
                    )
    return violations


def test_the_task_seven_modules_import_only_their_binding_tables(
    repository_root: Path,
) -> None:
    assert set(_ALLOWED_IMPORTS) == {
        _SUPERVISED_MODULE,
        _DURABLE_TEST_MODULE,
        _SUPERVISED_TEST_MODULE,
    }
    for label, allowed in _ALLOWED_IMPORTS.items():
        tree = _parse(repository_root / label)
        assert _import_pairs(tree) == allowed, label
        assert _boundary_violations(tree, label) == []
    # The shared support module is held to the denylist; its imports belong to
    # Tasks 1-6 as well.
    assert _boundary_violations(_parse(repository_root / _HARNESS_MODULE), "h") == []


def test_the_import_pin_notices_one_extra_import(repository_root: Path) -> None:
    for label, allowed in _ALLOWED_IMPORTS.items():
        source = (repository_root / label).read_text(encoding="utf-8")
        extra = ast.parse(source + "\nimport supervision_scenarios\n")
        assert _import_pairs(extra) - allowed == {("supervision_scenarios", "")}
        assert _boundary_violations(extra, label) != []


@pytest.mark.parametrize(("source", "word"), _NEGATIVE_CONTROLS)
def test_the_boundary_scanner_flags_every_forbidden_form(
    source: str, word: str
) -> None:
    violations = _boundary_violations(ast.parse(source), "probe.py")
    assert violations, source
    assert any(word.split()[0] in item for item in violations), violations


def test_the_boundary_scanner_accepts_the_binding_table_shapes() -> None:
    source = (
        "from doubles.experiments import FixedClock\n"
        "from contract.scenarios import SCENARIOS\n"
        "from crypto_lab.persistence.unit_of_work import SqliteUnitOfWork\n"
        "class Flow:\n    pass\n"
    )
    assert _boundary_violations(ast.parse(source), "probe.py") == []
