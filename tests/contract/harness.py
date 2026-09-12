"""The offline contract harness (Stage 6 plan section 11.3): a stand-in supervisor
for tests only.

``OfflineCommandHarness`` drives the merged Stage 5 lifecycle with the real
application operations, writes the request envelope of plan 6.1 under a
per-invocation command root, launches the stdlib-only fake adapter of
``tests/fake_adapters/fake_adapter.py`` as a child process with an interpreter
prefix, a list argument array, no shell and an empty environment block, moves the
child's stdout lines and stderr chunks through two reader threads, feeds every line
to the committed ``parse_protocol_line`` and ``InvocationEventLedger``, appends the
accepted events through ``EngineRunRepository.append_event``, applies the Stage 5
coupled terminal transitions when a line is rejected, the command deadline passes
or a cancellation is requested, parses the output file with the committed
byte-level parsers, observes the declared candidate files, and applies the verdict
through ``apply_command_semantic_outcome`` (validate and run) or
``reconcile_describe`` and ``describe_availability_observation`` (describe).

It is a **stand-in** for the Stage 7 process supervisor and is named so throughout:
its deadlines and heartbeat timer poll ``time.monotonic`` in test code, it claims
no production supervision coverage, it finalizes nothing, builds no core run
manifest and moves no run to a success state. The raw attempt token appears only in
the request file, the wire lines and the manifest file under the command root; every
projection the harness returns is walked by ``assert_token_absent``.

Task-local readings (recorded in the Task 8 ledger): ``CommandRun`` carries the
command root, the write-boundary difference, the replay count, the output bytes, the
live protocol summary and the rejection beside the plan's six fields; the clock is
advanced one second before each stdout line is parsed so replays are proven under an
advanced receipt clock; a killed child's native exit is recorded by enrichment; the
negotiated versions handed to every validate and run are the constant a described
``fake.conformant`` negotiates.
"""

from __future__ import annotations

import json
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import IO, Any, Final

from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.catalog import AdapterCatalogEntry, FrozenAdapterCatalog
from crypto_lab.adapters.commands import AdapterCommand, CommandResult, argument_array
from crypto_lab.adapters.diagnostics import (
    PROCESS_CANCELLED,
    PROCESS_DESCRIBE_TIMED_OUT,
    PROCESS_MISSING_HEARTBEAT,
    PROCESS_RUN_TIMED_OUT,
    PROCESS_STDERR_TRUNCATED,
    PROCESS_UNRECOGNIZED_PROCESS_EXIT,
    PROCESS_VALIDATE_TIMED_OUT,
    stage6_diagnostic,
)
from crypto_lab.adapters.envelopes import (
    DescribeRequestPayload,
    EngineRunRequest,
    NegotiatedVersions,
    build_engine_run_request,
    build_request_envelope,
    request_envelope_bytes,
    request_hash_of,
    request_material_hash,
)
from crypto_lab.adapters.events import (
    EventAcceptanceContext,
    EventAccepted,
    EventRejected,
    EventReplayed,
    HeartbeatPayload,
    InvocationEventLedger,
    ProtocolEventSummary,
    frame_protocol_lines,
    parse_protocol_line,
)
from crypto_lab.adapters.limits import (
    MAX_DESCRIPTOR_OUTPUT_BYTES,
    MAX_VALIDATION_RESULT_BYTES,
    PROTOCOL_VERSION,
    RESULT_MANIFEST_RELATIVE_PATH,
    ProtocolLimits,
)
from crypto_lab.adapters.manifests import (
    AdapterResultManifest,
    ManifestParse,
    ValidationResultParse,
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
from crypto_lab.adapters.sanitization import (
    BoundedStderrCapture,
    StderrCapture,
    token_present,
)
from crypto_lab.adapters.vocabulary import (
    ProtocolIntegrityStatus,
    ReconciliationVerdict,
)
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import (
    CommandInvocationRecord,
    ProcessIdentity,
    ProcessStartFacts,
)
from crypto_lab.domain.descriptors import (
    OperatingSystem,
    RuntimeAvailabilityObservation,
)
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.engine_run import AttemptTokenMaterial, EngineRunRecord
from crypto_lab.domain.experiment import (
    AdapterIdentity,
    EngineIdentity,
    ExperimentRecord,
    SelectedEngineSlot,
)
from crypto_lab.domain.hashing import _uuid4_shaped, sha256_bytes
from crypto_lab.domain.lifecycle import (
    RECOGNIZED_NATIVE_EXIT_VALUES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.experiment_service import (
    create_experiment,
    queue_experiment,
    transition_experiment,
)
from crypto_lab.experiments.invocation_service import (
    LinkedPair,
    begin_linked_launch,
    create_invocation,
    enrich_invocation,
    start_linked_run,
    transition_invocation,
    transition_invocation_and_run,
)
from crypto_lab.experiments.requests import (
    AttemptCreationRequest,
    CoupledTransitionRequest,
    ExperimentCreationRequest,
    ExperimentQueueRequest,
    ExperimentTransitionRequest,
    InvocationCreationRequest,
    InvocationEnrichmentRequest,
    InvocationTransitionRequest,
    LinkedLaunchRequest,
    LinkedStartRequest,
    RetryEvaluationRequest,
    RunTransitionRequest,
    SemanticOutcomeRequest,
    SuccessorCreationRequest,
)
from crypto_lab.experiments.retry import create_successor, evaluate_retry
from crypto_lab.experiments.run_service import create_attempt, transition_run
from crypto_lab.experiments.semantic_outcome import (
    SemanticOutcome,
    apply_command_semantic_outcome,
)
from doubles.experiments import (
    INSTANT,
    MATERIAL_HASH,
    SLOT_A,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    SequentialIdentitySource,
    sample_draft,
    sample_slot_compatibility,
)

_C = CommandInvocationState
_R = EngineRunState
_K = CommandKind

#: The fake adapter executable every scenario catalog points at (plan 11.1).
FAKE_ADAPTER_PATH: Final[Path] = (
    Path(__file__).resolve().parents[1] / "fake_adapters" / "fake_adapter.py"
)
FAKE_ADAPTER_VERSION: Final = "1.0.0"
FAKE_ENGINE: Final = EngineIdentity(engine_name="fake.engine", engine_version="1.0.0")
#: Plan 5.4: the harness's constant runtime facts for the availability observation.
FAKE_RUNTIME_VERSION: Final = "1.0.0"
FAKE_OPERATING_SYSTEM: Final = OperatingSystem.WINDOWS
OBSERVATION_VALIDITY: Final = timedelta(hours=1)
#: Plan 11.3 item 1: the interpreter-prefixed launch of the Python fake.
INTERPRETER_FLAGS: Final[tuple[str, ...]] = ("-I", "-B")
#: The fresh, non-inherited environment block (probed to start CPython here).
LAUNCH_ENVIRONMENT: Final[dict[str, str]] = {}
LAUNCH_SHELL: Final = False
HARNESS_SOURCE_COMPONENT: Final = "contract.harness"
SUPERVISOR_INSTANCE_ID: Final = "offline-harness"
#: A stable namespaced label for every transition the harness asks for.
REASON: Final = "HARNESS.STEP"
REQUEST_FILE_NAME: Final = "request.json"
OUTPUT_FILE_NAME: Final = "output.json"
#: Row 47: the file attempt 2's fake copies to ``--output``.
STALE_OUTPUT_FILE_NAME: Final = "stale-output.json"
#: What a described ``fake.conformant`` negotiates (plan 5.2, 5.3).
DEFAULT_NEGOTIATED: Final = NegotiatedVersions(
    protocol_version=PROTOCOL_VERSION,
    schema_versions=CORE_PROTOCOL_SUPPORT.schema_versions,
    capability_vocabulary_version=CORE_PROTOCOL_SUPPORT.vocabulary_versions[0],
)
POLL_INTERVAL_SECONDS: Final = 0.02
#: A describe has no attempt token, yet the stderr fold redacts against one; this
#: NUL-delimited sentinel (built at runtime, never emitted by any fake) keeps a
#: describe's stderr text untouched instead of redacting a non-secret identity.
DESCRIBE_STDERR_SENTINEL: Final = chr(0) + "describe-has-no-attempt-token" + chr(0)
#: Row 50: at most this many seeds are tried for a letter-leading token.
MAX_SEED_PROBES: Final = 64
_TIMEOUT_CODE_OF: Final[dict[CommandKind, str]] = {
    _K.DESCRIBE: PROCESS_DESCRIBE_TIMED_OUT,
    _K.VALIDATE: PROCESS_VALIDATE_TIMED_OUT,
    _K.RUN: PROCESS_RUN_TIMED_OUT,
}
_COUPLED_RUN_TARGET: Final[dict[CommandInvocationState, EngineRunState]] = {
    _C.PROTOCOL_FAILED: _R.FAILED,
    _C.TIMED_OUT: _R.TIMED_OUT,
    _C.CANCELLED: _R.CANCELLED,
}

Tamper = Callable[[dict[str, Any]], None]


def _missing(value: object) -> bool:
    return value is MISSING


def _ok[T](result: Result[T]) -> T:
    if isinstance(result, Failure):
        codes = [item.error_code for item in result.diagnostics]
        messages = [item.message for item in result.diagnostics]
        raise AssertionError(f"operation failed: {codes} {messages}")
    assert isinstance(result, Success)
    return result.value


def fake_adapter_hash() -> str:
    """The catalog's ``executable_hash``: the sha256 of the script bytes."""
    return sha256_bytes(FAKE_ADAPTER_PATH.read_bytes())


def catalog_entry_for(adapter_name: str) -> AdapterCatalogEntry:
    """One catalog entry pointing at the fake script under the scenario's name."""
    return AdapterCatalogEntry(
        adapter_name=adapter_name,
        adapter_version=FAKE_ADAPTER_VERSION,
        engine=FAKE_ENGINE,
        executable_path=str(FAKE_ADAPTER_PATH),
        executable_hash=fake_adapter_hash(),
        runtime_metadata={},
    )


def catalog_for(adapter_name: str, clock: FixedClock) -> FrozenAdapterCatalog:
    """Plan 11.1: exactly the entry the scenario needs, one per scenario."""
    return FrozenAdapterCatalog((catalog_entry_for(adapter_name),), clock=clock)


def launch_arguments(command: AdapterCommand) -> tuple[str, ...]:
    """Plan 11.3 item 1: the test process's own interpreter, isolated and without
    bytecode writes, the fake script, then exactly ``argument_array(command)``."""
    return (
        sys.executable,
        *INTERPRETER_FLAGS,
        str(FAKE_ADAPTER_PATH),
        *argument_array(command),
    )


def _letter_leading_seed(seed: str) -> str:
    """Row 50: the first derived seed whose attempt token starts with a letter."""
    for probe in range(MAX_SEED_PROBES):
        candidate = f"{seed}-{probe}"
        if SequentialIdentitySource(candidate).new_attempt_token()[0].isalpha():
            return candidate
    raise AssertionError("no letter-leading attempt token within the probe budget")


def build_harness(
    root: Path,
    adapter_name: str,
    *,
    limits: ProtocolLimits,
    seed: str,
    letter_leading_token: bool = False,
) -> OfflineCommandHarness:
    """A harness over a fresh store, a fixed clock and a seeded identity source."""
    clock = FixedClock(INSTANT)
    identity = SequentialIdentitySource(
        _letter_leading_seed(seed) if letter_leading_token else seed
    )
    return OfflineCommandHarness(
        InMemoryBackingStore(),
        clock,
        identity,
        catalog_for(adapter_name, clock),
        root,
        limits,
    )


@dataclass(frozen=True, slots=True)
class CommandRun:
    """One finished command through the stand-in (plan 11.3 plus reading R1)."""

    command_result: CommandResult
    outcome: SemanticOutcome | None
    reconciliation: SemanticReconciliation | None
    observation: RuntimeAvailabilityObservation | None
    raw_stdout_lines: tuple[bytes, ...]
    work_dir: Path
    command_root: Path
    written_paths: frozenset[str]
    replayed_count: int
    output_bytes: bytes | None
    protocol_summary: ProtocolEventSummary | None
    rejection: EventRejected | None


@dataclass(slots=True)
class _Supervised:
    """What the child-process loop hands back to the command-specific epilogue."""

    invocation: CommandInvocationRecord
    run: EngineRunRecord | None
    ledger: InvocationEventLedger
    raw_lines: tuple[bytes, ...]
    rejection: EventRejected | None
    replayed: int
    stderr: StderrCapture
    diagnostics: tuple[Diagnostic, ...]
    stdout_bytes_seen: int
    written_paths: frozenset[str]


def _snapshot(root: Path) -> frozenset[str]:
    return frozenset(
        path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()
    )


def _pump(stream: IO[bytes], sink: queue.Queue[bytes | None]) -> None:
    """Move one pipe into a queue line by line; a partial tail arrives at EOF."""
    try:
        while True:
            chunk = stream.readline()
            if not chunk:
                break
            sink.put(chunk)
    finally:
        sink.put(None)


def _drain(source: queue.Queue[bytes | None]) -> tuple[list[bytes], bool]:
    """Every queued chunk and whether the end-of-stream sentinel was seen."""
    chunks: list[bytes] = []
    ended = False
    while True:
        try:
            item = source.get_nowait()
        except queue.Empty:
            return chunks, ended
        if item is None:
            ended = True
        else:
            chunks.append(item)


class OfflineCommandHarness:
    """The stand-in supervisor of plan 11.3; test-resident, never production."""

    def __init__(
        self,
        store: InMemoryBackingStore,
        clock: FixedClock,
        identity: SequentialIdentitySource,
        catalog: FrozenAdapterCatalog,
        root: Path,
        limits: ProtocolLimits,
    ) -> None:
        self.store = store
        self.clock = clock
        self.identity = identity
        self.catalog = catalog
        self.root = root
        self.limits = limits
        self._tokens: dict[str, str] = {}
        root.mkdir(parents=True, exist_ok=True)

    # -- Units of work and store inspection --------------------------------------------

    def _unit_of_work(self) -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(self.store, clock=self.clock)

    def stored_experiment(self, experiment_id: str) -> ExperimentRecord:
        (record,) = (
            item
            for item in self.store.committed_experiments()
            if item.experiment_id == experiment_id
        )
        return record

    def stored_run(self, run_id: str) -> EngineRunRecord:
        (record,) = (
            item for item in self.store.committed_engine_runs() if item.run_id == run_id
        )
        return record

    def stored_invocation(self, invocation_id: str) -> CommandInvocationRecord:
        (record,) = (
            item
            for item in self.store.committed_command_invocations()
            if item.invocation_id == invocation_id
        )
        return record

    def invocations_of(
        self, run_id: str, kind: CommandKind
    ) -> tuple[CommandInvocationRecord, ...]:
        return tuple(
            item
            for item in self.store.committed_command_invocations()
            if item.command_kind is kind
            and not _missing(item.run_id)
            and item.run_id == run_id
        )

    def diagnostic(self, diagnostic_id: str) -> Diagnostic:
        return self.store.diagnostics.live[diagnostic_id]

    def codes_of(self, diagnostic_ids: Iterable[str]) -> tuple[str, ...]:
        return tuple(self.diagnostic(item).error_code for item in diagnostic_ids)

    def primary_code_of(self, record: object) -> str | None:
        """The primary code of a reconciliation or of an invocation, if any."""
        if isinstance(record, SemanticReconciliation):
            primary = record.primary_diagnostic
            return None if _missing(primary) else primary.error_code
        if isinstance(record, CommandInvocationRecord):
            identity = record.primary_diagnostic_id
            return None if _missing(identity) else self.diagnostic(identity).error_code
        return None

    def token_for(self, run_id: str) -> str:
        """The raw attempt token the harness has held since ``create_attempt``."""
        return self._tokens[run_id]

    def _seed(self, diagnostic: Diagnostic) -> None:
        if diagnostic.diagnostic_id not in self.store.diagnostics.live:
            self.store.seed_diagnostic(diagnostic)

    def _mint(
        self,
        code: str,
        message: str,
        *,
        invocation_id: str,
        run: EngineRunRecord | None,
        causal_diagnostic_ids: tuple[str, ...] = (),
    ) -> Diagnostic:
        payload: dict[str, Any] = {}
        if run is not None:
            payload["experiment_id"] = run.experiment_id
            payload["run_id"] = run.run_id
        diagnostic = stage6_diagnostic(
            code,
            message,
            source_component=HARNESS_SOURCE_COMPONENT,
            timestamp_utc=self.clock.now_utc(),
            invocation_id=invocation_id,
            causal_diagnostic_ids=causal_diagnostic_ids,
            **payload,
        )
        self._seed(diagnostic)
        return diagnostic

    # -- The Stage 5 lifecycle, with the real operations ----------------------------

    def new_experiment(self, adapter_name: str) -> ExperimentRecord:
        """``DRAFT -> VALIDATED -> QUEUED`` with one selected slot for the adapter."""
        draft = sample_draft(
            selected_engine_slots=(
                SelectedEngineSlot(
                    logical_slot_id=SLOT_A,
                    slot_ordinal=0,
                    adapter=AdapterIdentity(
                        adapter_name=adapter_name, adapter_version=FAKE_ADAPTER_VERSION
                    ),
                    engine=FAKE_ENGINE,
                ),
            )
        )
        created = _ok(
            create_experiment(
                ExperimentCreationRequest(
                    schema_version="1.0.0",
                    spec_draft=draft,
                    material_base_configuration_hash=MATERIAL_HASH,
                ),
                unit_of_work=self._unit_of_work(),
                clock=self.clock,
                identity_source=self.identity,
            )
        )
        validated = _ok(
            transition_experiment(
                ExperimentTransitionRequest(
                    schema_version="1.0.0",
                    experiment_id=created.experiment_id,
                    expected_revision=created.revision,
                    target_state=ExperimentState.VALIDATED,
                    reason_code=REASON,
                ),
                unit_of_work=self._unit_of_work(),
                clock=self.clock,
            )
        )
        return _ok(
            queue_experiment(
                ExperimentQueueRequest(
                    schema_version="1.0.0",
                    experiment_id=validated.experiment_id,
                    expected_revision=validated.revision,
                    config_derived_retry_policy=validated.spec.retry_policy,
                    material_base_configuration_hash=MATERIAL_HASH,
                    slot_compatibility=sample_slot_compatibility(draft),
                ),
                unit_of_work=self._unit_of_work(),
                clock=self.clock,
            )
        )

    def _request_hash(self, experiment: ExperimentRecord, attempt_number: int) -> str:
        return request_material_hash(
            experiment=experiment,
            logical_slot_id=SLOT_A,
            attempt_number=attempt_number,
            negotiated=DEFAULT_NEGOTIATED,
            limits=self.limits,
        )

    def new_attempt(
        self, experiment: ExperimentRecord
    ) -> tuple[ExperimentRecord, EngineRunRecord]:
        """Attempt 1 of the slot; the raw token is held for the request material."""
        creation = _ok(
            create_attempt(
                AttemptCreationRequest(
                    schema_version="1.0.0",
                    experiment_id=experiment.experiment_id,
                    logical_slot_id=SLOT_A,
                    expected_experiment_revision=experiment.revision,
                    request_hash=self._request_hash(experiment, 1),
                ),
                unit_of_work=self._unit_of_work(),
                clock=self.clock,
                identity_source=self.identity,
            )
        )
        material = creation.attempt_token
        assert isinstance(material, AttemptTokenMaterial)
        self._tokens[creation.attempt.run_id] = material.attempt_token
        return creation.experiment, creation.attempt

    def successor(
        self, experiment: ExperimentRecord, predecessor: EngineRunRecord
    ) -> tuple[ExperimentRecord, EngineRunRecord]:
        """Row 47: ``evaluate_retry`` (``ALLOWED``), the durable delay, then
        ``create_successor`` with the attempt-2 request material."""
        decision = _ok(
            evaluate_retry(
                RetryEvaluationRequest(
                    schema_version="1.0.0",
                    experiment_id=experiment.experiment_id,
                    logical_slot_id=predecessor.logical_slot_id,
                    predecessor_run_id=predecessor.run_id,
                    expected_experiment_revision=experiment.revision,
                    expected_predecessor_revision=predecessor.revision,
                ),
                unit_of_work=self._unit_of_work(),
                clock=self.clock,
            )
        )
        self.clock.advance(decision.retry_policy.retry_delay_seconds)
        experiment = self.stored_experiment(experiment.experiment_id)
        creation = _ok(
            create_successor(
                SuccessorCreationRequest(
                    schema_version="1.0.0",
                    experiment_id=experiment.experiment_id,
                    logical_slot_id=predecessor.logical_slot_id,
                    predecessor_run_id=predecessor.run_id,
                    expected_experiment_revision=experiment.revision,
                    request_hash=self._request_hash(
                        experiment, decision.reserved_successor_attempt_number
                    ),
                ),
                unit_of_work=self._unit_of_work(),
                clock=self.clock,
                identity_source=self.identity,
            )
        )
        material = creation.attempt_token
        assert isinstance(material, AttemptTokenMaterial)
        self._tokens[creation.attempt.run_id] = material.attempt_token
        return creation.experiment, creation.attempt

    def _move_run(
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
        return _ok(
            transition_run(
                RunTransitionRequest.model_validate(payload),
                unit_of_work=self._unit_of_work(),
                clock=self.clock,
            )
        )

    def validating(self, run: EngineRunRecord) -> EngineRunRecord:
        """``PENDING -> VALIDATING``, the parent state of a ``VALIDATE``."""
        return self._move_run(run, _R.VALIDATING)

    def ready(self, run: EngineRunRecord) -> EngineRunRecord:
        """``PENDING -> VALIDATING -> READY`` with the slot's frozen observation, so
        no validate child is launched for a run row (plan 11.3 item 1)."""
        if run.state is _R.PENDING:
            run = self.validating(run)
        if run.state is _R.VALIDATING:
            experiment = self.stored_experiment(run.experiment_id)
            (slot,) = (
                entry
                for entry in experiment.slot_compatibility
                if entry.logical_slot_id == run.logical_slot_id
            )
            run = self._move_run(
                run,
                _R.READY,
                availability_observation_id=slot.availability_observation_id,
            )
        return run

    def _create_invocation(
        self,
        kind: CommandKind,
        adapter_name: str,
        adapter_version: str,
        *,
        run: EngineRunRecord | None,
        request_hash: str,
        timeout_seconds: int,
    ) -> CommandInvocationRecord:
        payload: dict[str, object] = {
            "schema_version": "1.0.0",
            "command_kind": kind,
            "adapter_name": adapter_name,
            "adapter_version": adapter_version,
            "request_hash": request_hash,
            "timeout_seconds": timeout_seconds,
        }
        if run is not None:
            payload["run_id"] = run.run_id
            payload["expected_run_revision"] = run.revision
        return _ok(
            create_invocation(
                InvocationCreationRequest.model_validate(payload),
                unit_of_work=self._unit_of_work(),
                clock=self.clock,
                identity_source=self.identity,
            )
        )

    def _transition(
        self,
        invocation: CommandInvocationRecord,
        target: CommandInvocationState,
        *,
        process_start: ProcessStartFacts | None = None,
        native_exit_value: int | None = None,
        primary: Diagnostic | None = None,
        diagnostic_ids: tuple[str, ...] = (),
    ) -> CommandInvocationRecord:
        payload: dict[str, object] = {
            "schema_version": "1.0.0",
            "invocation_id": invocation.invocation_id,
            "expected_revision": invocation.revision,
            "target_state": target,
            "reason_code": REASON,
            "diagnostic_ids": tuple(sorted(set(diagnostic_ids))),
        }
        if process_start is not None:
            payload["process_start"] = process_start
        if native_exit_value is not None:
            payload["native_exit_value"] = native_exit_value
        if primary is not None:
            payload["primary_diagnostic_id"] = primary.diagnostic_id
        return _ok(
            transition_invocation(
                InvocationTransitionRequest.model_validate(payload),
                unit_of_work=self._unit_of_work(),
                clock=self.clock,
            )
        )

    def _coupled(
        self,
        invocation: CommandInvocationRecord,
        run: EngineRunRecord,
        target: CommandInvocationState,
        *,
        primary: Diagnostic,
        diagnostic_ids: tuple[str, ...],
    ) -> LinkedPair:
        """A core-won terminal and its coupled run edge (plan 11.3 item 3)."""
        return _ok(
            transition_invocation_and_run(
                CoupledTransitionRequest(
                    schema_version="1.0.0",
                    invocation=InvocationTransitionRequest.model_validate(
                        {
                            "schema_version": "1.0.0",
                            "invocation_id": invocation.invocation_id,
                            "expected_revision": invocation.revision,
                            "target_state": target,
                            "reason_code": REASON,
                            "primary_diagnostic_id": primary.diagnostic_id,
                            "diagnostic_ids": tuple(
                                sorted({primary.diagnostic_id, *diagnostic_ids})
                            ),
                        }
                    ),
                    run=RunTransitionRequest.model_validate(
                        {
                            "schema_version": "1.0.0",
                            "run_id": run.run_id,
                            "expected_revision": run.revision,
                            "target_state": _COUPLED_RUN_TARGET[target],
                            "reason_code": REASON,
                            "primary_terminal_diagnostic_id": primary.diagnostic_id,
                        }
                    ),
                ),
                unit_of_work=self._unit_of_work(),
                clock=self.clock,
            )
        )

    def _enrich(
        self,
        invocation: CommandInvocationRecord,
        *,
        native_exit_value: int | None = None,
        additional_diagnostic_ids: tuple[str, ...] = (),
    ) -> CommandInvocationRecord:
        payload: dict[str, object] = {
            "schema_version": "1.0.0",
            "invocation_id": invocation.invocation_id,
            "expected_revision": invocation.revision,
            "additional_diagnostic_ids": tuple(sorted(set(additional_diagnostic_ids))),
        }
        if native_exit_value is not None:
            payload["native_exit_value"] = native_exit_value
        return _ok(
            enrich_invocation(
                InvocationEnrichmentRequest.model_validate(payload),
                unit_of_work=self._unit_of_work(),
                clock=self.clock,
            )
        )

    def launch_pair(self, run: EngineRunRecord, *, timeout_seconds: int) -> LinkedPair:
        """A ``RUN`` invocation against a ``READY`` run through ``begin_linked_launch``
        (``STARTING``/``STARTING``) without a child; the start-deadline case."""
        invocation = self._create_invocation(
            _K.RUN,
            run.adapter.adapter_name,
            run.adapter.adapter_version,
            run=run,
            request_hash=run.request_hash,
            timeout_seconds=timeout_seconds,
        )
        return _ok(
            begin_linked_launch(
                LinkedLaunchRequest(
                    schema_version="1.0.0",
                    invocation_id=invocation.invocation_id,
                    expected_invocation_revision=invocation.revision,
                    run_id=run.run_id,
                    expected_run_revision=run.revision,
                ),
                unit_of_work=self._unit_of_work(),
                clock=self.clock,
            )
        )

    def terminalize_timed_out(
        self,
        invocation: CommandInvocationRecord,
        run: EngineRunRecord,
        *,
        code: str,
        causal_diagnostic_ids: tuple[str, ...] = (),
    ) -> LinkedPair:
        """The terminal-mapping helper callable without a child (plan 11.3 item 4):
        the command's timeout code as the primary of the coupled ``TIMED_OUT``."""
        primary = self._mint(
            code,
            "the command deadline passed before the child completed",
            invocation_id=invocation.invocation_id,
            run=run,
            causal_diagnostic_ids=causal_diagnostic_ids,
        )
        return self._coupled(
            invocation,
            run,
            _C.TIMED_OUT,
            primary=primary,
            diagnostic_ids=causal_diagnostic_ids,
        )

    # -- Command roots and request material -----------------------------------------

    def _entry(self, adapter_name: str, adapter_version: str) -> AdapterCatalogEntry:
        return _ok(self.catalog.get(adapter_name, adapter_version))

    def _command_root(self, invocation: CommandInvocationRecord) -> Path:
        command_root = self.root / invocation.invocation_id
        command_root.mkdir(parents=True, exist_ok=False)
        return command_root

    def _write_request(
        self, command_root: Path, envelope_bytes: bytes, tamper: Tamper | None
    ) -> None:
        if tamper is not None:
            document = json.loads(envelope_bytes.decode("utf-8"))
            tamper(document)
            envelope_bytes = json.dumps(
                document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        (command_root / REQUEST_FILE_NAME).write_bytes(envelope_bytes)

    def _engine_run_request(self, run: EngineRunRecord) -> EngineRunRequest:
        return build_engine_run_request(
            run=run,
            experiment=self.stored_experiment(run.experiment_id),
            token=AttemptTokenMaterial(
                run_id=run.run_id, attempt_token=self.token_for(run.run_id)
            ),
            negotiated=DEFAULT_NEGOTIATED,
            limits=self.limits,
            created_at_utc=self.clock.now_utc(),
        )

    def _observation_id(self, invocation_id: str) -> str:
        return f"avail_{_uuid4_shaped(sha256_bytes(invocation_id.encode('utf-8')))}"

    # -- The three commands ---------------------------------------------------------

    def drive(
        self,
        adapter_name: str,
        command: CommandKind,
        *,
        timeout_seconds: int,
        cancel_after_first_heartbeat: bool = False,
    ) -> CommandRun:
        """The lifecycle prelude of plan 11.3 item 1, then the command itself."""
        if command is _K.DESCRIBE:
            return self.describe(
                adapter_name, FAKE_ADAPTER_VERSION, timeout_seconds=timeout_seconds
            )
        experiment = self.new_experiment(adapter_name)
        _experiment, run = self.new_attempt(experiment)
        if command is _K.VALIDATE:
            return self.validate(self.validating(run), timeout_seconds=timeout_seconds)
        return self.run(
            self.ready(run),
            timeout_seconds=timeout_seconds,
            cancel_after_first_heartbeat=cancel_after_first_heartbeat,
        )

    def describe(
        self, adapter_name: str, adapter_version: str, *, timeout_seconds: int
    ) -> CommandRun:
        entry = self._entry(adapter_name, adapter_version)
        payload = DescribeRequestPayload(
            bootstrap_schema_version="1.0.0",
            adapter_name=adapter_name,
            adapter_version=adapter_version,
            executable_hash=entry.executable_hash,
            core_supported_protocol_versions=CORE_PROTOCOL_SUPPORT.protocol_versions,
            core_supported_schema_versions=CORE_PROTOCOL_SUPPORT.schema_versions,
            core_capability_vocabulary_versions=CORE_PROTOCOL_SUPPORT.vocabulary_versions,
        )
        invocation = self._create_invocation(
            _K.DESCRIBE,
            adapter_name,
            adapter_version,
            run=None,
            request_hash=request_hash_of(payload),
            timeout_seconds=timeout_seconds,
        )
        invocation = self._transition(invocation, _C.STARTING)
        command_root = self._command_root(invocation)
        command = AdapterCommand(
            command_kind=_K.DESCRIBE,
            catalog_entry=entry,
            invocation_id=invocation.invocation_id,
            request_path=str(command_root / REQUEST_FILE_NAME),
            output_path=str(command_root / OUTPUT_FILE_NAME),
            timeout_seconds=timeout_seconds,
        )
        envelope = build_request_envelope(invocation=invocation, payload=payload)
        self._write_request(command_root, request_envelope_bytes(envelope), None)
        supervised = self._supervise(
            command,
            invocation,
            run=None,
            token=None,
            cancel_after_first_heartbeat=False,
        )
        invocation = supervised.invocation
        output_path = command_root / OUTPUT_FILE_NAME
        output_bytes = output_path.read_bytes() if output_path.is_file() else None
        reconciliation: SemanticReconciliation | None = None
        observation: RuntimeAvailabilityObservation | None = None
        parsed_output: Any = MISSING
        source_hash: Any = MISSING
        now = self.clock.now_utc()
        if invocation.state is _C.EXITED:
            parse: Any = MISSING
            if output_bytes is not None:
                parse = parse_bootstrap_descriptor(
                    output_bytes, max_bytes=MAX_DESCRIPTOR_OUTPUT_BYTES
                )
                source_hash = parse.source_hash
                if not _missing(parse.envelope):
                    parsed_output = parse.envelope
            reconciliation = reconcile_describe(
                invocation,
                parse,
                supervised.stdout_bytes_seen,
                catalog_entry=entry,
                now_utc=now,
            )
            if reconciliation.diagnostics:
                for diagnostic in reconciliation.diagnostics:
                    self._seed(diagnostic)
                invocation = self._enrich(
                    invocation,
                    additional_diagnostic_ids=tuple(
                        item.diagnostic_id for item in reconciliation.diagnostics
                    ),
                )
            observation = self._observation(
                entry,
                invocation,
                verdict=reconciliation.verdict,
                primary_code=self.primary_code_of(reconciliation),
                descriptor=reconciliation.descriptor,
            )
        elif invocation.state is _C.TIMED_OUT:
            observation = self._observation(
                entry,
                invocation,
                verdict=None,
                primary_code=PROCESS_DESCRIBE_TIMED_OUT,
                descriptor=MISSING,
            )
        command_result = CommandResult(
            invocation=invocation,
            parsed_output=parsed_output,
            parsed_output_source_hash=source_hash,
            protocol_integrity=ProtocolIntegrityStatus.INTACT,
            accepted_events=(),
            diagnostics=supervised.diagnostics,
            stderr=supervised.stderr,
            cancelled=invocation.state is _C.CANCELLED,
            timed_out=invocation.state is _C.TIMED_OUT,
        )
        return CommandRun(
            command_result=command_result,
            outcome=None,
            reconciliation=reconciliation,
            observation=observation,
            raw_stdout_lines=supervised.raw_lines,
            work_dir=command_root,
            command_root=command_root,
            written_paths=supervised.written_paths,
            replayed_count=0,
            output_bytes=output_bytes,
            protocol_summary=None,
            rejection=None,
        )

    def _observation(
        self,
        entry: AdapterCatalogEntry,
        invocation: CommandInvocationRecord,
        *,
        verdict: ReconciliationVerdict | None,
        primary_code: str | None,
        descriptor: Any,
    ) -> RuntimeAvailabilityObservation:
        now = self.clock.now_utc()
        return describe_availability_observation(
            adapter_name=entry.adapter_name,
            adapter_version=entry.adapter_version,
            verdict=MISSING if verdict is None else verdict,
            primary_code=MISSING if primary_code is None else primary_code,
            descriptor=descriptor,
            observation_id=self._observation_id(invocation.invocation_id),
            executable_path=entry.executable_path,
            executable_hash=entry.executable_hash,
            runtime_version=FAKE_RUNTIME_VERSION,
            operating_system=FAKE_OPERATING_SYSTEM,
            observed_at_utc=now,
            expires_at_utc=now + OBSERVATION_VALIDITY,
        )

    def validate(
        self,
        run: EngineRunRecord,
        *,
        timeout_seconds: int,
        stale_output_bytes: bytes | None = None,
        tamper: Tamper | None = None,
    ) -> CommandRun:
        entry = self._entry(run.adapter.adapter_name, run.adapter.adapter_version)
        invocation = self._create_invocation(
            _K.VALIDATE,
            run.adapter.adapter_name,
            run.adapter.adapter_version,
            run=run,
            request_hash=run.request_hash,
            timeout_seconds=timeout_seconds,
        )
        invocation = self._transition(invocation, _C.STARTING)
        command_root = self._command_root(invocation)
        command = AdapterCommand(
            command_kind=_K.VALIDATE,
            catalog_entry=entry,
            invocation_id=invocation.invocation_id,
            request_path=str(command_root / REQUEST_FILE_NAME),
            output_path=str(command_root / OUTPUT_FILE_NAME),
            timeout_seconds=timeout_seconds,
        )
        envelope = build_request_envelope(
            invocation=invocation, payload=self._engine_run_request(run)
        )
        self._write_request(command_root, request_envelope_bytes(envelope), tamper)
        if stale_output_bytes is not None:
            (command_root / STALE_OUTPUT_FILE_NAME).write_bytes(stale_output_bytes)
        token = self.token_for(run.run_id)
        supervised = self._supervise(
            command,
            invocation,
            run=run,
            token=token,
            cancel_after_first_heartbeat=False,
        )
        # Plan 11.3 item 4: the output file is read and parsed for an EXITED
        # invocation alone; a core-won terminal never reconciles the child's output.
        output_path = command_root / OUTPUT_FILE_NAME
        output_bytes: bytes | None = None
        parse: Any = MISSING
        if supervised.invocation.state is _C.EXITED and output_path.is_file():
            output_bytes = output_path.read_bytes()
            parse = parse_validation_result(
                output_bytes, max_bytes=MAX_VALIDATION_RESULT_BYTES, token=token
            )
        return self._conclude(
            supervised,
            command_root=command_root,
            work_dir=command_root,
            parse=parse,
            observations=(),
            output_bytes=output_bytes,
        )

    def run(
        self,
        run: EngineRunRecord,
        *,
        timeout_seconds: int,
        cancel_after_first_heartbeat: bool = False,
        tamper: Tamper | None = None,
        work_dir_tail: str | None = None,
    ) -> CommandRun:
        entry = self._entry(run.adapter.adapter_name, run.adapter.adapter_version)
        invocation = self._create_invocation(
            _K.RUN,
            run.adapter.adapter_name,
            run.adapter.adapter_version,
            run=run,
            request_hash=run.request_hash,
            timeout_seconds=timeout_seconds,
        )
        launched = _ok(
            begin_linked_launch(
                LinkedLaunchRequest(
                    schema_version="1.0.0",
                    invocation_id=invocation.invocation_id,
                    expected_invocation_revision=invocation.revision,
                    run_id=run.run_id,
                    expected_run_revision=run.revision,
                ),
                unit_of_work=self._unit_of_work(),
                clock=self.clock,
            )
        )
        invocation, run = launched.invocation, launched.run
        command_root = self._command_root(invocation)
        request = self._engine_run_request(run)
        tail = (
            request.assigned_work_dir.relative_path
            if work_dir_tail is None
            else work_dir_tail
        )
        work_dir = command_root.joinpath(*tail.split("/"))
        work_dir.mkdir(parents=True, exist_ok=False)
        command = AdapterCommand(
            command_kind=_K.RUN,
            catalog_entry=entry,
            invocation_id=invocation.invocation_id,
            request_path=str(command_root / REQUEST_FILE_NAME),
            work_dir=str(work_dir),
            result_path=str(work_dir / RESULT_MANIFEST_RELATIVE_PATH),
            timeout_seconds=timeout_seconds,
        )
        envelope = build_request_envelope(invocation=invocation, payload=request)
        self._write_request(command_root, request_envelope_bytes(envelope), tamper)
        token = self.token_for(run.run_id)
        supervised = self._supervise(
            command,
            invocation,
            run=run,
            token=token,
            cancel_after_first_heartbeat=cancel_after_first_heartbeat,
        )
        # Plan 11.3 item 4: the manifest is read, parsed and the candidates observed
        # for an EXITED invocation alone; a core-won terminal reconciles nothing.
        result_path = work_dir / RESULT_MANIFEST_RELATIVE_PATH
        manifest_bytes: bytes | None = None
        parse: Any = MISSING
        observations: tuple[CandidateObservation, ...] = ()
        if supervised.invocation.state is _C.EXITED:
            if result_path.is_file():
                manifest_bytes = result_path.read_bytes()
                parse = parse_result_manifest(
                    manifest_bytes,
                    max_bytes=self.limits.max_manifest_bytes,
                    token=token,
                )
            observations = self._observe_candidates(
                work_dir, supervised.ledger.summary(), parse, token
            )
        return self._conclude(
            supervised,
            command_root=command_root,
            work_dir=work_dir,
            parse=parse,
            observations=observations,
            output_bytes=manifest_bytes,
        )

    def _observe_candidates(
        self,
        work_dir: Path,
        summary: ProtocolEventSummary,
        parse: Any,
        token: str,
    ) -> tuple[CandidateObservation, ...]:
        """Plan 11.3 item 4: the union of event-declared and (for a success
        manifest) manifest-declared paths, observed where the file exists."""
        declared: list[str] = [
            record.payload.relative_path for record in summary.artifact_declarations
        ]
        if isinstance(parse, ManifestParse) and isinstance(
            parse.manifest, AdapterResultManifest
        ):
            manifest = parse.manifest
            if manifest.semantic_status.value in (
                "SUCCEEDED",
                "SUCCEEDED_WITH_WARNINGS",
            ):
                declared.extend(
                    item.relative_path
                    for item in manifest.candidate_artifacts
                    if item.relative_path not in declared
                )
        observations: list[CandidateObservation] = []
        encoded = token.encode("utf-8")
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

    def _conclude(
        self,
        supervised: _Supervised,
        *,
        command_root: Path,
        work_dir: Path,
        parse: Any,
        observations: tuple[CandidateObservation, ...],
        output_bytes: bytes | None,
    ) -> CommandRun:
        """The validate/run epilogue: the operation for an ``EXITED`` invocation."""
        invocation = supervised.invocation
        run = supervised.run
        assert run is not None
        summary = supervised.ledger.summary()
        parsed_output: Any = MISSING
        source_hash: Any = MISSING
        if isinstance(parse, ValidationResultParse):
            source_hash = parse.source_hash
            if not _missing(parse.result):
                parsed_output = parse.result
        elif isinstance(parse, ManifestParse):
            source_hash = parse.source_hash
            if not _missing(parse.manifest):
                parsed_output = parse.manifest
        outcome: SemanticOutcome | None = None
        reconciliation: SemanticReconciliation | None = None
        if invocation.state is _C.EXITED:
            stored_run = self.stored_run(run.run_id)
            request = SemanticOutcomeRequest(
                schema_version="1.0.0",
                invocation_id=invocation.invocation_id,
                expected_invocation_revision=invocation.revision,
                run_id=stored_run.run_id,
                expected_run_revision=stored_run.revision,
                parsed_output=parse,
                protocol_summary=summary,
                candidate_observations=observations,
                negotiated_versions=DEFAULT_NEGOTIATED,
            )
            outcome = _ok(
                apply_command_semantic_outcome(
                    request, unit_of_work=self._unit_of_work(), clock=self.clock
                )
            )
            invocation = outcome.invocation
            if not _missing(outcome.reconciliation):
                reconciliation = outcome.reconciliation
                for diagnostic in reconciliation.diagnostics:
                    self._seed(diagnostic)
        command_result = CommandResult(
            invocation=invocation,
            parsed_output=parsed_output,
            parsed_output_source_hash=source_hash,
            protocol_integrity=(
                ProtocolIntegrityStatus.VIOLATED
                if invocation.state is _C.PROTOCOL_FAILED
                else ProtocolIntegrityStatus.INTACT
            ),
            accepted_events=supervised.ledger.events,
            diagnostics=supervised.diagnostics,
            stderr=supervised.stderr,
            cancelled=invocation.state is _C.CANCELLED,
            timed_out=invocation.state is _C.TIMED_OUT,
        )
        return CommandRun(
            command_result=command_result,
            outcome=outcome,
            reconciliation=reconciliation,
            observation=None,
            raw_stdout_lines=supervised.raw_lines,
            work_dir=work_dir,
            command_root=command_root,
            written_paths=supervised.written_paths,
            replayed_count=supervised.replayed,
            output_bytes=output_bytes,
            protocol_summary=summary,
            rejection=supervised.rejection,
        )

    # -- The child-process loop (plan 11.3 items 1-3) --------------------------------

    def _start(
        self,
        invocation: CommandInvocationRecord,
        run: EngineRunRecord | None,
        facts: ProcessStartFacts,
    ) -> tuple[CommandInvocationRecord, EngineRunRecord | None]:
        """``STARTING -> RUNNING`` with the process facts; linked for a ``RUN``."""
        if invocation.command_kind is _K.RUN:
            assert run is not None
            pair = _ok(
                start_linked_run(
                    LinkedStartRequest(
                        schema_version="1.0.0",
                        invocation_id=invocation.invocation_id,
                        expected_invocation_revision=invocation.revision,
                        run_id=run.run_id,
                        expected_run_revision=run.revision,
                        process_start=facts,
                    ),
                    unit_of_work=self._unit_of_work(),
                    clock=self.clock,
                )
            )
            return pair.invocation, pair.run
        return self._transition(invocation, _C.RUNNING, process_start=facts), run

    def _append(self, accepted: EventAccepted) -> None:
        transaction = self._unit_of_work().begin()
        _ok(transaction.engine_runs.append_event(accepted.event))
        _ok(transaction.commit())

    def _supervise(
        self,
        command: AdapterCommand,
        invocation: CommandInvocationRecord,
        *,
        run: EngineRunRecord | None,
        token: str | None,
        cancel_after_first_heartbeat: bool,
    ) -> _Supervised:
        kind = invocation.command_kind
        entry = command.catalog_entry
        command_root = Path(command.request_path).parent
        before = _snapshot(command_root)
        argv = list(launch_arguments(command))
        stdout_queue: queue.Queue[bytes | None] = queue.Queue()
        stderr_queue: queue.Queue[bytes | None] = queue.Queue()
        capture = BoundedStderrCapture(
            limit=self.limits.max_stderr_bytes,
            token=DESCRIBE_STDERR_SENTINEL if token is None else token,
        )
        ledger = InvocationEventLedger()
        raw_lines: list[bytes] = []
        rejection: EventRejected | None = None
        replayed = 0
        stdout_bytes_seen = 0
        pending = b""
        missing_heartbeat: Diagnostic | None = None
        terminal: CommandInvocationState | None = None
        process = subprocess.Popen(  # noqa: S603 - reviewed fixed interpreter boundary
            argv,
            shell=False,
            env=LAUNCH_ENVIRONMENT,
            cwd=str(command_root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            started = time.monotonic()
            deadline = started + command.timeout_seconds
            heartbeat_deadline = (
                None
                if kind is _K.DESCRIBE
                else started + self.limits.missing_heartbeat_seconds
            )
            assert process.stdout is not None
            assert process.stderr is not None
            readers = (
                threading.Thread(
                    target=_pump, args=(process.stdout, stdout_queue), daemon=True
                ),
                threading.Thread(
                    target=_pump, args=(process.stderr, stderr_queue), daemon=True
                ),
            )
            for reader in readers:
                reader.start()
            facts = ProcessStartFacts(
                pid_identity=ProcessIdentity(
                    pid=process.pid,
                    creation_identity=f"{SUPERVISOR_INSTANCE_ID}:{process.pid}",
                    executable_path=entry.executable_path,
                    executable_hash=entry.executable_hash,
                    supervisor_instance_id=SUPERVISOR_INSTANCE_ID,
                ),
                process_started_at_utc=self.clock.now_utc(),
            )
            invocation, run = self._start(invocation, run, facts)
            stdout_ended = False
            stderr_ended = False
            cancel_requested = False
            while terminal is None:
                chunks, ended = _drain(stdout_queue)
                stdout_ended = stdout_ended or ended
                for chunk in chunks:
                    if kind is _K.DESCRIBE:
                        stdout_bytes_seen += len(chunk)
                        continue
                    lines, pending = frame_protocol_lines(
                        pending, chunk, max_event_bytes=self.limits.max_event_bytes
                    )
                    for line in lines:
                        if rejection is not None:
                            break
                        assert run is not None
                        outcome, ledger = self._parse(line, invocation, run, ledger)
                        raw_lines.append(line)
                        if isinstance(outcome, EventAccepted):
                            self._append(outcome)
                            if isinstance(outcome.event.payload, HeartbeatPayload):
                                heartbeat_deadline = (
                                    time.monotonic()
                                    + self.limits.missing_heartbeat_seconds
                                )
                                if cancel_after_first_heartbeat:
                                    cancel_requested = True
                        elif isinstance(outcome, EventReplayed):
                            replayed += 1
                        else:
                            rejection = outcome
                if (
                    stdout_ended
                    and pending
                    and rejection is None
                    and kind is not (_K.DESCRIBE)
                ):
                    # Plan 7.1 rule 3: an unterminated fragment at end of stream.
                    assert run is not None
                    outcome, ledger = self._parse(pending, invocation, run, ledger)
                    raw_lines.append(pending)
                    pending = b""
                    assert isinstance(outcome, EventRejected)
                    rejection = outcome
                chunks, ended = _drain(stderr_queue)
                stderr_ended = stderr_ended or ended
                for chunk in chunks:
                    capture.feed(chunk)
                if rejection is not None:
                    process.kill()
                    terminal = _C.PROTOCOL_FAILED
                    break
                now = time.monotonic()
                if cancel_requested:
                    process.kill()
                    terminal = _C.CANCELLED
                    break
                if now >= deadline:
                    process.kill()
                    terminal = _C.TIMED_OUT
                    break
                if (
                    heartbeat_deadline is not None
                    and now >= heartbeat_deadline
                    and missing_heartbeat is None
                ):
                    missing_heartbeat = self._mint(
                        PROCESS_MISSING_HEARTBEAT,
                        "no heartbeat arrived within the missing-heartbeat threshold",
                        invocation_id=invocation.invocation_id,
                        run=run,
                    )
                if process.poll() is not None and stdout_ended and stderr_ended:
                    terminal = _C.EXITED
                    break
                time.sleep(POLL_INTERVAL_SECONDS)
            native_exit = process.wait()
            for reader in readers:
                reader.join()
            chunks, _ended = _drain(stderr_queue)
            for chunk in chunks:
                capture.feed(chunk)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        stderr = capture.finish()
        diagnostics: list[Diagnostic] = []
        if missing_heartbeat is not None:
            diagnostics.append(missing_heartbeat)
        secondary_ids = tuple(item.diagnostic_id for item in diagnostics)
        if terminal is _C.EXITED:
            primary: Diagnostic | None = None
            if native_exit not in RECOGNIZED_NATIVE_EXIT_VALUES:
                primary = self._mint(
                    PROCESS_UNRECOGNIZED_PROCESS_EXIT,
                    "the child exited with an unrecognized native value",
                    invocation_id=invocation.invocation_id,
                    run=run,
                )
                diagnostics.append(primary)
            invocation = self._transition(
                invocation,
                _C.EXITED,
                native_exit_value=native_exit,
                primary=primary,
                diagnostic_ids=() if primary is None else (primary.diagnostic_id,),
            )
            additional = list(secondary_ids)
            if stderr.truncated:
                truncated = self._mint(
                    PROCESS_STDERR_TRUNCATED,
                    "stderr exceeded the snapshot's max_stderr_bytes and was truncated",
                    invocation_id=invocation.invocation_id,
                    run=run,
                )
                diagnostics.append(truncated)
                additional.append(truncated.diagnostic_id)
            if additional:
                invocation = self._enrich(
                    invocation, additional_diagnostic_ids=tuple(additional)
                )
        else:
            if terminal is _C.PROTOCOL_FAILED:
                assert rejection is not None
                primary = rejection.diagnostic
                self._seed(primary)
            elif terminal is _C.TIMED_OUT:
                primary = self._mint(
                    _TIMEOUT_CODE_OF[kind],
                    "the command deadline passed before the child completed",
                    invocation_id=invocation.invocation_id,
                    run=run,
                    causal_diagnostic_ids=secondary_ids,
                )
            else:
                primary = self._mint(
                    PROCESS_CANCELLED,
                    "the harness cancelled the command",
                    invocation_id=invocation.invocation_id,
                    run=run,
                )
            diagnostics.append(primary)
            assert terminal is not None
            if run is None:
                invocation = self._transition(
                    invocation,
                    terminal,
                    primary=primary,
                    diagnostic_ids=(primary.diagnostic_id, *secondary_ids),
                )
            else:
                pair = self._coupled(
                    invocation,
                    run,
                    terminal,
                    primary=primary,
                    diagnostic_ids=secondary_ids,
                )
                invocation, run = pair.invocation, pair.run
            # Plan 11.3 item 3: the native exit, once reaped, by enrichment.
            invocation = self._enrich(invocation, native_exit_value=native_exit)
        unique: dict[str, Diagnostic] = {
            item.diagnostic_id: item for item in diagnostics
        }
        return _Supervised(
            invocation=invocation,
            run=run,
            ledger=ledger,
            raw_lines=tuple(raw_lines),
            rejection=rejection,
            replayed=replayed,
            stderr=stderr,
            diagnostics=tuple(unique.values()),
            stdout_bytes_seen=stdout_bytes_seen,
            written_paths=_snapshot(command_root) - before,
        )

    def _parse(
        self,
        line: bytes,
        invocation: CommandInvocationRecord,
        run: EngineRunRecord,
        ledger: InvocationEventLedger,
    ) -> tuple[EventAccepted | EventReplayed | EventRejected, InvocationEventLedger]:
        """One framed unit through the committed parser; reading R2 advances the
        receipt clock first. Returns the outcome and the successor ledger."""
        self.clock.advance(1)
        outcome = parse_protocol_line(
            line,
            acceptance=EventAcceptanceContext(
                invocation=invocation,
                attempt_token_hash=run.attempt_token_hash,
                max_event_bytes=self.limits.max_event_bytes,
                ledger=ledger,
                clock=self.clock,
            ),
        )
        return outcome, ledger.accept(outcome)


# --- Token safety (plan 11.3 item 5) --------------------------------------------------


def token_free_projections(command_run: CommandRun) -> tuple[object, ...]:
    """The object set ``assert_token_absent`` walks: every ``RunEvent``, the sanitized
    manifest, every ``Diagnostic``, the ``CommandResult`` (its ``parsed_output``
    excluded only when it is an ``AdapterResultManifest``) and the stderr capture."""
    result = command_run.command_result
    items: list[object] = list(result.accepted_events)
    items.extend(result.diagnostics)
    reconciliation = command_run.reconciliation
    if reconciliation is not None:
        items.extend(reconciliation.diagnostics)
        if not _missing(reconciliation.sanitized_manifest):
            items.append(reconciliation.sanitized_manifest)
    if isinstance(result.parsed_output, AdapterResultManifest):
        items.append(result.model_dump(mode="json", exclude={"parsed_output"}))
    else:
        items.append(result)
    if not _missing(result.stderr):
        items.append(result.stderr)
    return tuple(items)


def assert_token_absent(objects: Iterable[object], token: str) -> None:
    """Fail on any occurrence of the raw token in the canonical JSON or ``repr`` of
    any of ``objects`` (plan 11.3 item 5)."""
    for item in objects:
        text = canonical_json_bytes(item).decode("utf-8")
        assert token not in text, "the raw attempt token reached a core projection"
        assert token not in repr(item), "the raw attempt token reached a repr"


def _raw_line_of(command_run: CommandRun, wire_event_hash: str) -> bytes:
    for line in command_run.raw_stdout_lines:
        body = line[:-1] if line.endswith(b"\n") else line
        if sha256_bytes(body) == wire_event_hash:
            return line
    raise AssertionError("an accepted event has no raw stdout line")


def assert_token_only_in_wire_material(command_run: CommandRun, token: str) -> None:
    """Plan 11.3 item 5: absence outside the trust-class-W set and presence in each
    W object that exists -- the request file, every accepted-envelope line and, when
    the parsed output is a manifest, the manifest file and that parsed model."""
    absence: list[object] = list(token_free_projections(command_run))
    if command_run.outcome is not None:
        absence.append(command_run.outcome)
    if command_run.reconciliation is not None:
        absence.append(command_run.reconciliation)
    assert_token_absent(absence, token)
    encoded = token.encode("utf-8")
    request_bytes = (command_run.command_root / REQUEST_FILE_NAME).read_bytes()
    assert encoded in request_bytes, "the request file must carry the raw token"
    result = command_run.command_result
    for event in result.accepted_events:
        assert encoded in _raw_line_of(command_run, event.wire_event_hash)
    parsed = result.parsed_output
    if isinstance(parsed, AdapterResultManifest):
        manifest_bytes = (
            command_run.work_dir / RESULT_MANIFEST_RELATIVE_PATH
        ).read_bytes()
        assert encoded in manifest_bytes
        assert parsed.attempt_token == token
    else:
        assert not isinstance(parsed, AdapterResultManifest)
