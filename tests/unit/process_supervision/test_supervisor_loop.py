"""Stage 7 Task 6: the supervision loop over the scripted controller (plan 6.3-6.7).

The first RED of Task 6 is the ``crypto_lab.process_supervision.supervisor`` import
below and the Task 6 doubles it drives. The ``scripted`` fixture of plan 9.5 seeds one
``PENDING`` invocation per command kind over ``InMemoryBackingStore`` (a RUN pair whose
run is ``READY``, a VALIDATE pair whose run is ``VALIDATING``, a token-free describe),
registers the matching request material on a real ``Stage5InvocationLifecycle`` wrapped
in the recording double, and drives ``WindowsProcessSupervisor`` with the scripted
controller, whose every ``wait(0.0)`` poll advances the fixture clock, so deadlines,
grace windows and the pipe-holder window elapse in ticks rather than wall time. One
test launches a real child (the venv launcher over the merged fake adapter) through the
Windows controller so the loop is proven against a real pipe before Task 8.

Test-local readings, declared rather than inferred silently:

- The plan's Step 1 tests are copied verbatim except for the strict-mypy fixture
  annotation, a ``# noqa: E501`` on a definition line the formatter cannot shorten,
  the PT018 splits of the plan's compound asserts (every clause kept, in order) and
  the cancellation test's tuple-returning lambda, written as a typed hook because
  strict mypy rejects a tuple of two ``None`` results.
- Plan 9.5's ``valid_heartbeat_line`` is a module-level helper over the active fixture,
  so the plan's tests keep their exact shape.
- Carried note A: the missed-heartbeat test slices ``wait_bounds`` by the tick index at
  which the diagnostic was minted, captured by an observer hook on ``HEARTBEAT_MISSED``
  (observer entries are not one-to-one with ticks); the plan's observer-index slice is
  kept as a second, looser assertion.
"""

from __future__ import annotations

import asyncio
import errno
import json
from collections.abc import Callable, Coroutine
from dataclasses import fields
from datetime import timedelta
from pathlib import Path
from typing import Any, Final

import pytest
from pydantic.experimental.missing_sentinel import MISSING

from contract.harness import DEFAULT_NEGOTIATED
from crypto_lab.adapters.catalog import AdapterCatalogEntry
from crypto_lab.adapters.commands import AdapterCommand
from crypto_lab.adapters.diagnostics import (
    PROCESS_CANCELLED,
    PROCESS_MISSING_HEARTBEAT,
    PROCESS_START_TIMED_OUT,
    PROCESS_STDERR_TRUNCATED,
    PROCESS_UNRECOGNIZED_PROCESS_EXIT,
    PROTOCOL_STDOUT_CONTAMINATION,
    stage6_diagnostic,
)
from crypto_lab.adapters.envelopes import (
    DescribeRequestPayload,
    request_hash_of,
    request_material_hash,
)
from crypto_lab.adapters.events import EventRejected
from crypto_lab.adapters.limits import (
    MAX_RESULT_MANIFEST_BYTES,
    MIN_EVENT_LINE_BYTES,
    MIN_STDERR_BYTES,
    ProtocolLimits,
)
from crypto_lab.adapters.manifests import ManifestParse
from crypto_lab.adapters.negotiation import (
    CORE_PROTOCOL_SUPPORT,
    BootstrapDescriptorEnvelope,
    DescriptorParse,
)
from crypto_lab.adapters.sanitization import StderrCapture
from crypto_lab.adapters.vocabulary import ProtocolIntegrityStatus
from crypto_lab.domain.command_invocation import (
    CommandInvocationRecord,
    ProcessIdentity,
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
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure, Success
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
)
from crypto_lab.experiments.experiment_service import cancel_experiment
from crypto_lab.experiments.invocation_service import transition_invocation_and_run
from crypto_lab.experiments.requests import (
    CancelExperimentRequest,
    CoupledTransitionRequest,
    InvocationTransitionRequest,
    RunTransitionRequest,
)
from crypto_lab.experiments.run_service import transition_run
from crypto_lab.experiments.supervision_lifecycle import (
    RequestMaterial,
    Stage5InvocationLifecycle,
)
from crypto_lab.process_supervision import supervisor as supervisor_module
from crypto_lab.process_supervision.cancellation import ThreadSafeCancellationToken
from crypto_lab.process_supervision.diagnostics import (
    PROCESS_FORCED_TERMINATION,
    PROCESS_GRACEFUL_INTERRUPT_UNAVAILABLE,
    PROCESS_JOB_OBJECT_UNAVAILABLE,
    PROCESS_LAUNCH_FAILED,
)
from crypto_lab.process_supervision.models import (
    FORCED_TERMINATION_EXIT_CODE,
    TICK_SECONDS,
    CleanupAction,
    CleanupFailure,
    InterruptOutcome,
    LaunchFailure,
    ProcessPresence,
    SupervisionOutcome,
    SupervisionTraceKind,
    parse_creation_identity,
)
from crypto_lab.process_supervision.readers import PipeReader, wait_for_chunk
from crypto_lab.process_supervision.roots import PathPreflight, plan_command_paths
from crypto_lab.process_supervision.windows_process import WindowsProcessController
from doubles.experiments import (
    INSTANT,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    SequentialIdentitySource,
    sample_draft,
    sample_experiment,
    sample_invocation,
    sample_run,
)
from doubles.supervision import (
    InMemoryReconciliationSource,
    RealtimeMonotonicClock,
    RecordingLifecycle,
    RecordingObserver,
    ScriptedProcessController,
    SeedingDiagnosticRecorder,
    SupervisionFixedClock,
    build_supervisor,
    supervised_catalog_entry_for,
)

_INSTANT: Final = INSTANT
#: The seeded experiments and runs were created a minute before the clock (the Task 5
#: precedent), so their sample ``updated_at_utc`` never lies after the first swap.
_SEEDED_AT: Final = INSTANT - timedelta(seconds=60)
_ADAPTER_NAME: Final = "fake.conformant"
_ADAPTER_VERSION: Final = "1.0.0"
_FAKE_ENGINE: Final = EngineIdentity(engine_name="fake.engine", engine_version="1.0.0")
_SUPERVISOR: Final = "process_supervision.supervisor"
#: Plan 9.5: the merged heartbeat rows' limits (interval 1 s, threshold 2 s) so a
#: missed heartbeat is due before the 4 s deadline; the event and stderr ceilings are
#: lowered to their floors so the oversized-line and truncation rows stay small.
LIMITS: Final = ProtocolLimits(
    max_event_bytes=MIN_EVENT_LINE_BYTES,
    max_manifest_bytes=MAX_RESULT_MANIFEST_BYTES,
    max_stderr_bytes=MIN_STDERR_BYTES,
    heartbeat_interval_seconds=1,
    missing_heartbeat_seconds=2,
)
TIMEOUT_SECONDS: Final = 4

CANCELLED: Final = CommandInvocationState.CANCELLED
TIMED_OUT: Final = CommandInvocationState.TIMED_OUT
EXITED: Final = CommandInvocationState.EXITED
PROTOCOL_FAILED: Final = CommandInvocationState.PROTOCOL_FAILED
FAILED_TO_START: Final = CommandInvocationState.FAILED_TO_START
RUNNING: Final = CommandInvocationState.RUNNING
STARTING: Final = CommandInvocationState.STARTING
PENDING: Final = CommandInvocationState.PENDING
RUNNING_COMMITTED: Final = SupervisionTraceKind.RUNNING_COMMITTED
EVENT_ACCEPTED: Final = SupervisionTraceKind.EVENT_ACCEPTED
HEARTBEAT_MISSED: Final = SupervisionTraceKind.HEARTBEAT_MISSED
TERMINAL_DECIDED: Final = SupervisionTraceKind.TERMINAL_DECIDED
TERMINAL_COMMITTED: Final = SupervisionTraceKind.TERMINAL_COMMITTED
INTERRUPT_SENT: Final = SupervisionTraceKind.INTERRUPT_SENT
FORCED_TERMINATION: Final = SupervisionTraceKind.FORCED_TERMINATION
EXIT_REAPED: Final = SupervisionTraceKind.EXIT_REAPED
ENRICHMENT_COMMITTED: Final = SupervisionTraceKind.ENRICHMENT_COMMITTED
ABSENT: Final = ProcessPresence.ABSENT
#: The six kinds named in the cancellation test's expected list (plan Task 6).
ORDER_KINDS: Final = frozenset(
    {
        TERMINAL_DECIDED,
        TERMINAL_COMMITTED,
        INTERRUPT_SENT,
        FORCED_TERMINATION,
        EXIT_REAPED,
        ENRICHMENT_COMMITTED,
    }
)


# --------------------------------------------------------------------------
# Helpers (``ok`` and ``codes_of`` as in Task 3; the rest per plan Task 6)
# --------------------------------------------------------------------------


def codes_of(result: object) -> tuple[str, ...]:
    assert isinstance(result, Failure), result
    return tuple(diagnostic.error_code for diagnostic in result.diagnostics)


def ok[T](result: Success[T] | Failure) -> T:
    assert isinstance(result, Success), result
    return result.value


def token() -> ThreadSafeCancellationToken:
    return ThreadSafeCancellationToken()


def run[T](coroutine: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coroutine)


_active: _Scripted | None = None


def _fixture() -> _Scripted:
    assert _active is not None, "the scripted fixture is not active"
    return _active


def valid_heartbeat_line(
    sequence: int = 1, *, activity_counter: int | None = None
) -> bytes:
    """One framed ``HEARTBEAT`` line for the seeded run's token (plan Task 6)."""
    return _fixture().heartbeat_line(sequence, activity_counter=activity_counter)


def primary(record: CommandInvocationRecord) -> Diagnostic:
    identity = record.primary_diagnostic_id
    assert isinstance(identity, str), record
    return _fixture().store.diagnostics.live[identity]


def primary_code(record: CommandInvocationRecord) -> str:
    return primary(record).error_code


def causal_ids(diagnostic: Diagnostic) -> tuple[str, ...]:
    return tuple(diagnostic.causal_diagnostic_ids)


def causal_codes(diagnostic: Diagnostic) -> tuple[str, ...]:
    return _fixture().codes_of_ids(causal_ids(diagnostic))


def kinds_of(outcome: SupervisionOutcome) -> tuple[SupervisionTraceKind, ...]:
    return tuple(entry.kind for entry in outcome.trace)


# --------------------------------------------------------------------------
# The ``scripted`` fixture of plan 9.5
# --------------------------------------------------------------------------


class _Scripted:
    """One store, one clock, three seeded commands, one scripted controller."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.root = tmp_path / "supervision"
        self.root.mkdir()
        self.clock = SupervisionFixedClock(_INSTANT)
        self.entry = supervised_catalog_entry_for(_ADAPTER_NAME)
        self.preflight: Any = MISSING
        self.timeout_seconds = TIMEOUT_SECONDS
        self.limits = LIMITS
        self.wait_bounds: list[float] = []

        def recording(source: Any, timeout_seconds: float) -> Any:
            self.wait_bounds.append(timeout_seconds)
            return wait_for_chunk(source, timeout_seconds)

        # The wrapper replaces the name ``supervisor.py`` imports from ``readers.py``.
        monkeypatch.setattr(supervisor_module, "wait_for_chunk", recording)
        self._seed_counter = 0
        self.reset()

    # -- Seeding ------------------------------------------------------------------

    def rebuild(
        self,
        *,
        entry: AdapterCatalogEntry | None = None,
        root: Path | None = None,
        preflight: PathPreflight | None = None,
    ) -> None:
        """``reset`` over another catalog entry, supervision root or injected probe."""
        if entry is not None:
            self.entry = entry
        if root is not None:
            self.root = root
        if preflight is not None:
            self.preflight = preflight
        self.reset()

    def command_of(self, kind: CommandKind) -> AdapterCommand:
        return {
            CommandKind.RUN: self.run_command,
            CommandKind.VALIDATE: self.validate_command,
            CommandKind.DESCRIBE: self.describe_command,
        }[kind]

    def run_of(self, kind: CommandKind) -> str:
        return {
            CommandKind.RUN: self.run_id,
            CommandKind.VALIDATE: self.validate_run_id,
        }[kind]

    def experiment_of(self, kind: CommandKind) -> str:
        return {
            CommandKind.RUN: self.experiment_id,
            CommandKind.VALIDATE: self.validate_experiment_id,
        }[kind]

    def reset(self) -> None:
        """A fresh store, invocation, run and script for a second ``invoke``."""
        self._seed_counter += 1
        self.store = InMemoryBackingStore()
        self.identity = SequentialIdentitySource(f"task6-{self._seed_counter}")
        self.unit_of_work = InMemoryUnitOfWork(self.store, clock=self.clock)
        self.recorder = SeedingDiagnosticRecorder(self.store)
        self._materials: dict[str, RequestMaterial] = {}
        self._tokens: dict[str, str] = {}
        self._run_of: dict[str, str] = {}
        self.experiment_id, self.run_id, self.invocation_id = self._seed_pair(
            CommandKind.RUN, EngineRunState.READY
        )
        (
            self.validate_experiment_id,
            self.validate_run_id,
            self.validate_invocation_id,
        ) = self._seed_pair(CommandKind.VALIDATE, EngineRunState.VALIDATING)
        self.describe_invocation_id = self._seed_describe()
        self.inner_lifecycle = self._build_lifecycle(self.unit_of_work)
        self.lifecycle = RecordingLifecycle(self.inner_lifecycle)
        self.controller = ScriptedProcessController(clock=self.clock)
        self.observer = RecordingObserver()
        self.supervisor = build_supervisor(
            lifecycle=self.lifecycle,
            controller=self.controller,
            clock=self.clock,
            supervision_root=str(self.root),
            preflight=self.preflight,
            observers=(self.observer, self.controller),
        )
        self.run_command = self._command(
            CommandKind.RUN, self.invocation_id, self.run_id
        )
        self.validate_command = self._command(
            CommandKind.VALIDATE, self.validate_invocation_id, self.validate_run_id
        )
        self.describe_command = self._command(
            CommandKind.DESCRIBE, self.describe_invocation_id, None
        )

    def _seed_pair(
        self, kind: CommandKind, run_state: EngineRunState
    ) -> tuple[str, str, str]:
        slot = SelectedEngineSlot(
            logical_slot_id=self.identity.new_logical_slot_id(),
            slot_ordinal=0,
            adapter=AdapterIdentity(
                adapter_name=_ADAPTER_NAME, adapter_version=_ADAPTER_VERSION
            ),
            engine=_FAKE_ENGINE,
        )
        experiment_id = self.identity.new_experiment_id()
        experiment = sample_experiment(
            ExperimentState.RUNNING,
            experiment_id=experiment_id,
            draft=sample_draft(selected_engine_slots=(slot,)),
            created_at_utc=_SEEDED_AT,
        )
        self.store.experiments.live[experiment_id] = experiment
        compatibility = experiment.slot_compatibility
        assert isinstance(compatibility, tuple)
        (frozen,) = compatibility
        run_id = self.identity.new_run_id()
        attempt_token = self.identity.new_attempt_token()
        run = sample_run(
            run_state,
            run_id=run_id,
            experiment_id=experiment_id,
            logical_slot_id=slot.logical_slot_id,
            adapter=slot.adapter,
            engine=slot.engine,
            request_hash=request_material_hash(
                experiment=experiment,
                logical_slot_id=slot.logical_slot_id,
                attempt_number=1,
                negotiated=DEFAULT_NEGOTIATED,
                limits=LIMITS,
            ),
            attempt_token=attempt_token,
            availability_observation_id=frozen.availability_observation_id,
            created_at_utc=_SEEDED_AT,
        )
        self.store.engine_runs.live[run_id] = run
        invocation_id = self.identity.new_invocation_id()
        self.store.command_invocations.live[invocation_id] = sample_invocation(
            PENDING,
            kind=kind,
            invocation_id=invocation_id,
            run_id=run_id,
            adapter_name=_ADAPTER_NAME,
            adapter_version=_ADAPTER_VERSION,
            request_hash=run.request_hash,
            timeout_seconds=TIMEOUT_SECONDS,
        )
        self._materials[invocation_id] = RequestMaterial(
            token=AttemptTokenMaterial(run_id=run_id, attempt_token=attempt_token),
            negotiated_versions=DEFAULT_NEGOTIATED,
            limits=LIMITS,
        )
        self._tokens[invocation_id] = attempt_token
        self._run_of[invocation_id] = run_id
        return experiment_id, run_id, invocation_id

    def _seed_describe(self) -> str:
        support = CORE_PROTOCOL_SUPPORT
        payload = DescribeRequestPayload(
            bootstrap_schema_version="1.0.0",
            adapter_name=_ADAPTER_NAME,
            adapter_version=_ADAPTER_VERSION,
            executable_hash=self.entry.executable_hash,
            core_supported_protocol_versions=support.protocol_versions,
            core_supported_schema_versions=support.schema_versions,
            core_capability_vocabulary_versions=support.vocabulary_versions,
        )
        invocation_id = self.identity.new_invocation_id()
        self.store.command_invocations.live[invocation_id] = sample_invocation(
            PENDING,
            kind=CommandKind.DESCRIBE,
            invocation_id=invocation_id,
            adapter_name=_ADAPTER_NAME,
            adapter_version=_ADAPTER_VERSION,
            request_hash=request_hash_of(payload),
            timeout_seconds=TIMEOUT_SECONDS,
        )
        self._materials[invocation_id] = RequestMaterial(describe_payload=payload)
        return invocation_id

    def _build_lifecycle(
        self, unit_of_work: InMemoryUnitOfWork
    ) -> Stage5InvocationLifecycle:
        lifecycle = Stage5InvocationLifecycle(
            unit_of_work=unit_of_work, clock=self.clock, diagnostics=self.recorder
        )
        for invocation_id, material in self._materials.items():
            lifecycle.register_request_material(invocation_id, material)
        return lifecycle

    def _command(
        self, kind: CommandKind, invocation_id: str, run_id: str | None
    ) -> AdapterCommand:
        paths = plan_command_paths(
            str(self.root),
            command_kind=kind,
            invocation_id=invocation_id,
            run_id=MISSING if run_id is None else run_id,
        )
        facts: dict[str, object] = {
            "command_kind": kind,
            "catalog_entry": self.entry,
            "invocation_id": invocation_id,
            "request_path": paths.request_path,
            "timeout_seconds": TIMEOUT_SECONDS,
        }
        if kind is CommandKind.RUN:
            facts["work_dir"] = paths.work_dir
            facts["result_path"] = paths.result_path
        else:
            facts["output_path"] = paths.output_path
        return AdapterCommand.model_validate(facts)

    # -- Pass-through script fields -------------------------------------------------

    @property
    def stdout_chunks(self) -> list[bytes]:
        return self.controller.stdout_chunks

    @stdout_chunks.setter
    def stdout_chunks(self, value: list[bytes]) -> None:
        self.controller.stdout_chunks = value

    @property
    def stderr_chunks(self) -> list[bytes]:
        return self.controller.stderr_chunks

    @stderr_chunks.setter
    def stderr_chunks(self, value: list[bytes]) -> None:
        self.controller.stderr_chunks = value

    @property
    def exit_after(self) -> int | None:
        return self.controller.exit_after

    @exit_after.setter
    def exit_after(self, value: int | None) -> None:
        self.controller.exit_after = value

    @property
    def exit_code(self) -> int:
        return self.controller.exit_code

    @exit_code.setter
    def exit_code(self, value: int) -> None:
        self.controller.exit_code = value

    @property
    def hold_stdout_open(self) -> bool:
        return self.controller.hold_stdout_open

    @hold_stdout_open.setter
    def hold_stdout_open(self, value: bool) -> None:
        self.controller.hold_stdout_open = value

    @property
    def hold_stderr_open(self) -> bool:
        return self.controller.hold_stderr_open

    @hold_stderr_open.setter
    def hold_stderr_open(self, value: bool) -> None:
        self.controller.hold_stderr_open = value

    @property
    def release_on_terminate(self) -> bool:
        return self.controller.release_on_terminate

    @release_on_terminate.setter
    def release_on_terminate(self, value: bool) -> None:
        self.controller.release_on_terminate = value

    def advance_per_tick(self, seconds: float) -> None:
        """The controller advances the clock by ``seconds`` on every ``wait(0.0)``."""
        self.controller.advance_per_poll = seconds

    def step_utc_backwards_before(self, method: str) -> None:
        """A ``before`` hook that rewinds only the UTC instant by one second."""
        self.lifecycle.before(method, lambda: self.clock.rewind_utc(1))

    # -- Lifecycle-bound helpers ----------------------------------------------------

    def stored_run(self, run_id: str | None = None) -> EngineRunRecord:
        return self.store.engine_runs.live[self.run_id if run_id is None else run_id]

    def stored_invocation(
        self, invocation_id: str | None = None
    ) -> CommandInvocationRecord:
        key = self.invocation_id if invocation_id is None else invocation_id
        return self.store.command_invocations.live[key]

    def stored_experiment(self, experiment_id: str | None = None) -> ExperimentRecord:
        key = self.experiment_id if experiment_id is None else experiment_id
        return self.store.experiments.live[key]

    def _mint_cancelled(self, invocation_id: str) -> Diagnostic:
        run = self.stored_run(self._run_of[invocation_id])
        diagnostic = stage6_diagnostic(
            PROCESS_CANCELLED,
            "task6 external move",
            source_component="doubles.supervision.test",
            timestamp_utc=self.clock.now_utc(),
            experiment_id=run.experiment_id,
            run_id=run.run_id,
            invocation_id=invocation_id,
        )
        ok(self.recorder.record(diagnostic))
        return diagnostic

    def cancel_run_externally(self, invocation_id: str | None = None) -> None:
        """Move only the run to ``CANCELLED``, as an external run transition would."""
        key = self.invocation_id if invocation_id is None else invocation_id
        run = self.stored_run(self._run_of[key])
        ok(
            transition_run(
                RunTransitionRequest(
                    schema_version="1.0.0",
                    run_id=run.run_id,
                    expected_revision=run.revision,
                    target_state=EngineRunState.CANCELLED,
                    reason_code="TASK6.EXTERNAL_MOVE",
                    primary_terminal_diagnostic_id=self._mint_cancelled(
                        key
                    ).diagnostic_id,
                ),
                unit_of_work=self.unit_of_work,
                clock=self.clock,
            )
        )

    def terminalize_invocation_externally(
        self, invocation_id: str | None = None
    ) -> None:
        """Write the invocation's own coupled ``CANCELLED`` so the supervisor's next
        write finds a terminal record."""
        key = self.invocation_id if invocation_id is None else invocation_id
        record = self.stored_invocation(key)
        run = self.stored_run(self._run_of[key])
        cancelled = self._mint_cancelled(key)
        ok(
            transition_invocation_and_run(
                CoupledTransitionRequest(
                    schema_version="1.0.0",
                    invocation=InvocationTransitionRequest(
                        schema_version="1.0.0",
                        invocation_id=key,
                        expected_revision=record.revision,
                        target_state=CANCELLED,
                        reason_code="TASK6.EXTERNAL_MOVE",
                        primary_diagnostic_id=cancelled.diagnostic_id,
                        diagnostic_ids=(cancelled.diagnostic_id,),
                    ),
                    run=RunTransitionRequest(
                        schema_version="1.0.0",
                        run_id=run.run_id,
                        expected_revision=run.revision,
                        target_state=EngineRunState.CANCELLED,
                        reason_code="TASK6.EXTERNAL_MOVE",
                        primary_terminal_diagnostic_id=cancelled.diagnostic_id,
                    ),
                ),
                unit_of_work=self.unit_of_work,
                clock=self.clock,
            )
        )

    def cancel_experiment_externally(self, experiment_id: str | None = None) -> None:
        experiment = self.stored_experiment(experiment_id)
        ok(
            cancel_experiment(
                CancelExperimentRequest(
                    schema_version="1.0.0",
                    experiment_id=experiment.experiment_id,
                    expected_revision=experiment.revision,
                    correlation_id="task6-cancel",
                ),
                unit_of_work=self.unit_of_work,
                clock=self.clock,
            )
        )

    def start_invocation_externally(self, invocation_id: str | None = None) -> None:
        """Another actor drives the seeded ``PENDING`` invocation to ``STARTING``."""
        key = self.invocation_id if invocation_id is None else invocation_id
        other = self._build_lifecycle(InMemoryUnitOfWork(self.store, clock=self.clock))
        ok(
            other.begin_start(
                key, expected_revision=self.stored_invocation(key).revision
            )
        )

    def missing_heartbeat_id(self, invocation_id: str | None = None) -> str:
        key = self.invocation_id if invocation_id is None else invocation_id
        (identity,) = (
            diagnostic.diagnostic_id
            for diagnostic in self.store.diagnostics.live.values()
            if diagnostic.error_code == PROCESS_MISSING_HEARTBEAT
            and diagnostic.invocation_id == key
        )
        return identity

    def codes_of_ids(self, ids: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            self.store.diagnostics.live[identity].error_code for identity in ids
        )

    def heartbeat_line(
        self,
        sequence: int = 1,
        *,
        activity_counter: int | None = None,
        invocation_id: str | None = None,
        **updates: Any,
    ) -> bytes:
        key = self.invocation_id if invocation_id is None else invocation_id
        self._seed_counter += 1
        document: dict[str, Any] = {
            "schema_version": "1.0.0",
            "protocol_version": "1.0.0",
            "event_id": (
                f"evt_{
                    _uuid4_shaped(
                        sha256_bytes(
                            f'task6:{key}:{sequence}:{self._seed_counter}'.encode()
                        )
                    )
                }"
            ),
            "invocation_id": key,
            "run_id": self._run_of[key],
            "attempt_token": self._tokens[key],
            "sequence": sequence,
            "event_type": "HEARTBEAT",
            "timestamp_utc": "2026-09-07T11:59:59Z",
            "payload": {
                "activity_counter": sequence
                if activity_counter is None
                else activity_counter,
                "phase": "warmup",
            },
        }
        document.update(updates)
        return (
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
            + b"\n"
        )

    def raw_token(self, invocation_id: str | None = None) -> str:
        key = self.invocation_id if invocation_id is None else invocation_id
        return self._tokens[key]


@pytest.fixture
def scripted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    global _active  # the plan's module-level helpers read the active fixture
    fixture = _Scripted(tmp_path, monkeypatch)
    _active = fixture
    yield fixture
    _active = None


# --------------------------------------------------------------------------
# The plan's Step 1 tests, verbatim
# --------------------------------------------------------------------------


def test_a_rejection_wins_over_an_exit_observed_in_the_same_tick(
    scripted: _Scripted,
) -> None:
    scripted.stdout_chunks = [valid_heartbeat_line(sequence=1), b"not json\n"]
    scripted.exit_after = 1
    outcome = run(
        scripted.supervisor.invoke(scripted.run_command, ThreadSafeCancellationToken())
    )
    record = ok(outcome).command_result.invocation
    assert (
        record.state is CommandInvocationState.PROTOCOL_FAILED
    )  # EOF follows the last chunk, so the rejection is decided first
    assert scripted.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    assert scripted.controller.interrupt_calls == 0
    assert scripted.lifecycle.calls.count("enrich") == 1
    assert record.native_exit_value == 0  # the root's own reaped exit


def test_cancellation_beats_the_deadline_and_is_enriched_once(
    scripted: _Scripted,
) -> None:
    token = ThreadSafeCancellationToken()

    def cancel_and_pass_the_deadline(_entry: object) -> None:
        # the plan's tuple-returning lambda, as a typed hook for strict mypy
        token.request_cancellation()
        scripted.clock.advance(scripted.timeout_seconds + 1)

    scripted.observer.on(
        SupervisionTraceKind.RUNNING_COMMITTED, cancel_and_pass_the_deadline
    )
    scripted.advance_per_tick(1.0)  # the grace window elapses in ticks, not wall time
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token))
    ).command_result.invocation
    assert record.state is CommandInvocationState.CANCELLED
    assert scripted.stored_run().state is EngineRunState.CANCELLED
    assert [e.kind for e in scripted.observer.entries if e.kind in ORDER_KINDS] == [
        TERMINAL_DECIDED,
        TERMINAL_COMMITTED,
        INTERRUPT_SENT,
        FORCED_TERMINATION,
        EXIT_REAPED,
        ENRICHMENT_COMMITTED,
    ]


def test_a_cancellation_after_launch_but_before_the_handoff_forces_without_an_interrupt(
    scripted: _Scripted,
) -> None:
    token = ThreadSafeCancellationToken()
    scripted.controller.on_launch = lambda: token.request_cancellation()
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token))
    ).command_result.invocation
    assert (record.state, record.process_created) == (CANCELLED, False)
    assert not isinstance(
        record.native_exit_value, int
    )  # no exit pair; no `MISSING` inside a tuple equality (§2.6)
    assert scripted.controller.interrupt_calls == 0
    assert scripted.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]


def test_a_cancellation_before_begin_start_never_launches_and_still_enriches_once(
    scripted: _Scripted,
) -> None:
    token = ThreadSafeCancellationToken()
    token.request_cancellation()
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token))
    ).command_result.invocation
    assert (record.state, record.process_created, record.cleanup_complete) == (
        CANCELLED,
        False,
        True,
    )
    assert scripted.stored_run().state is EngineRunState.CANCELLED
    assert scripted.controller.launches == ()
    assert scripted.lifecycle.calls.count("enrich") == 1


def test_a_run_cancelled_externally_around_the_launch_is_honored_as_a_cancellation(
    scripted: _Scripted,
) -> None:
    scripted.lifecycle.before("begin_start", lambda: scripted.cancel_run_externally())
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is CommandInvocationState.CANCELLED
    assert record.process_created is False
    scripted.reset()
    scripted.lifecycle.before(
        "record_process_start", lambda: scripted.cancel_run_externally()
    )
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is CommandInvocationState.CANCELLED
    assert scripted.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    assert scripted.lifecycle.calls.count("resolve_external_winner") == 1


def test_a_refused_exited_write_is_a_defect_and_moves_nothing(
    scripted: _Scripted,
) -> None:
    scripted.lifecycle.fail(
        "record_terminal", INVARIANT_VIOLATION
    )  # one-shot, on the EXITED write
    scripted.exit_after = 1
    failure = run(scripted.supervisor.invoke(scripted.run_command, token()))
    assert codes_of(failure) == (INVARIANT_VIOLATION,)
    assert scripted.stored_invocation().state is CommandInvocationState.RUNNING
    assert scripted.stored_run().state is EngineRunState.RUNNING
    assert "resolve_external_winner" not in scripted.lifecycle.calls
    assert scripted.lifecycle.calls.count("record_terminal") == 1


def test_a_terminal_write_refused_by_a_run_race_is_reissued_once_on_the_alone_path(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    scripted.lifecycle.fail(
        "record_terminal", CONCURRENCY_CONFLICT
    )  # the coupled swap lost to an external transition_run
    scripted.lifecycle.before(
        "record_terminal", lambda: scripted.cancel_run_externally()
    )
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is CommandInvocationState.EXITED
    assert scripted.lifecycle.calls.count("record_terminal") == 2
    assert (
        scripted.stored_run().state is EngineRunState.CANCELLED
    )  # left as the core left it: the alone path


def test_a_cancelled_experiment_before_begin_start_never_launches(
    scripted: _Scripted,
) -> None:
    scripted.lifecycle.before(
        "begin_start", lambda: scripted.cancel_experiment_externally()
    )
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert (record.state, record.process_created) == (CANCELLED, False)
    assert scripted.controller.launches == ()
    assert scripted.stored_run().state is EngineRunState.CANCELLED
    assert scripted.lifecycle.calls.count("resolve_external_winner") == 1


def test_a_backlog_after_the_exit_is_drained_not_treated_as_a_pipe_holder(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    scripted.stdout_chunks = [valid_heartbeat_line(sequence=i + 1) for i in range(3000)]
    # the drain takes real reader-thread turns; 4000 polls before the fake deadline,
    # 1000 idle polls before the pipe-holder window
    scripted.advance_per_tick(0.001)
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is CommandInvocationState.EXITED
    assert (
        sum(
            1
            for e in scripted.observer.entries
            if e.kind is SupervisionTraceKind.EVENT_ACCEPTED
        )
        == 3000
    )
    assert not any(
        e.kind is SupervisionTraceKind.FORCED_TERMINATION
        for e in scripted.observer.entries
    )
    assert scripted.controller.terminate_calls == []


def test_a_pipe_holder_the_kill_cannot_reach_is_terminated_once_and_times_out(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    scripted.hold_stdout_open = True
    scripted.release_on_terminate = False
    scripted.advance_per_tick(0.5)
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is CommandInvocationState.TIMED_OUT
    assert record.cleanup_complete
    assert scripted.controller.terminate_calls == [
        FORCED_TERMINATION_EXIT_CODE
    ]  # step 8 once; the PROCESS_GONE branch terminates nothing again
    assert (
        sum(
            1
            for e in scripted.observer.entries
            if e.kind is SupervisionTraceKind.FORCED_TERMINATION
        )
        == 1
    )
    stopped = next(
        e
        for e in scripted.observer.entries
        if e.kind is SupervisionTraceKind.CLEANUP_ACTION
        and e.facts["action"] == "STDOUT_READER_STOPPED"
    )
    assert (
        stopped.facts["ended_by"] == "CANCELLED"
    )  # the double's cancel_read released the held read


def test_a_flush_rejection_after_a_pipe_holder_kill_does_not_terminate_twice(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    scripted.hold_stdout_open = True
    scripted.stdout_chunks = [b'{"unterminated']
    scripted.advance_per_tick(0.5)
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is CommandInvocationState.PROTOCOL_FAILED
    assert scripted.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    assert scripted.lifecycle.calls.count("enrich") == 1
    forced = [
        e
        for e in scripted.observer.entries
        if e.kind is SupervisionTraceKind.FORCED_TERMINATION
    ]
    assert len(forced) == 1
    assert forced[0].facts["reason"] == "pipe_holder"


def test_a_root_that_exits_while_a_descendant_holds_stdout_is_forced_and_still_exits(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    scripted.hold_stdout_open = True
    scripted.advance_per_tick(0.5)
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is CommandInvocationState.EXITED
    assert record.native_exit_value == 0
    assert PROCESS_FORCED_TERMINATION in scripted.codes_of_ids(record.diagnostic_ids)


def test_a_deadline_passing_before_the_handoff_times_out_from_starting_without_process_facts(  # noqa: E501
    scripted: _Scripted,
) -> None:
    scripted.controller.on_launch = lambda: scripted.clock.advance(
        scripted.timeout_seconds + 1
    )
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert (record.state, record.process_created) == (TIMED_OUT, False)
    assert not isinstance(record.native_exit_value, int)  # no exit pair (§2.6)
    assert primary_code(record) == PROCESS_START_TIMED_OUT
    assert scripted.stored_run().state is EngineRunState.TIMED_OUT


def test_a_missed_heartbeat_is_minted_once_and_never_terminates(
    scripted: _Scripted,
) -> None:
    scripted.stdout_chunks = [valid_heartbeat_line(sequence=1)]
    scripted.advance_per_tick(0.5)
    minted_tick: list[int] = []
    scripted.observer.on(
        SupervisionTraceKind.HEARTBEAT_MISSED,
        lambda _entry: minted_tick.append(len(scripted.wait_bounds)),
    )  # carried note A: the wait count at the minting tick, not the entry index
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is CommandInvocationState.TIMED_OUT
    assert (
        scripted.codes_of_ids(record.diagnostic_ids).count(PROCESS_MISSING_HEARTBEAT)
        == 1
    )
    assert causal_ids(primary(record)) == (scripted.missing_heartbeat_id(),)
    missed_at = next(
        i
        for i, e in enumerate(scripted.observer.entries)
        if e.kind is SupervisionTraceKind.HEARTBEAT_MISSED
    )
    bounds_after_mint = scripted.wait_bounds[
        missed_at:
    ]  # §6.3 step 9: a minted monitor no longer lowers the bound
    assert bounds_after_mint
    assert all(0.0 < b <= TICK_SECONDS for b in bounds_after_mint)  # never a busy wait
    (tick,) = minted_tick
    bounds_from_minting_tick = scripted.wait_bounds[tick:]
    assert bounds_from_minting_tick
    assert all(0.0 < b <= TICK_SECONDS for b in bounds_from_minting_tick)
    assert (
        scripted.controller.polls_between(
            SupervisionTraceKind.HEARTBEAT_MISSED, SupervisionTraceKind.TERMINAL_DECIDED
        )
        <= scripted.timeout_seconds / 0.5 + 1
    )  # sanity bound only


def test_an_external_terminal_winner_is_returned_not_overwritten(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    scripted.lifecycle.before(
        "record_terminal", lambda: scripted.terminalize_invocation_externally()
    )
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    assert outcome.command_result.invocation.state is CommandInvocationState.CANCELLED
    assert any(
        e.kind is SupervisionTraceKind.EXTERNAL_TERMINAL_WINNER for e in outcome.trace
    )


def test_a_lost_enrichment_swap_reloads_once_and_leaves_a_reconciliation_target(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    scripted.lifecycle.fail("enrich", CONCURRENCY_CONFLICT)
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    assert (
        scripted.lifecycle.calls.count("enrich") == 1
    )  # the intercepted call is recorded; no second attempt
    assert outcome.command_result.invocation == scripted.stored_invocation()
    assert outcome.command_result.invocation.cleanup_complete is False
    assert any(
        e.kind is SupervisionTraceKind.EXTERNAL_TERMINAL_WINNER for e in outcome.trace
    )
    assert outcome.command_result.invocation.invocation_id in {
        r.invocation_id
        for r in ok(
            InMemoryReconciliationSource(scripted.store).list_reconciliation_targets()
        )
    }


def test_an_own_request_defect_terminates_the_child_and_returns_the_failure(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    scripted.step_utc_backwards_before("record_terminal")
    failure = run(scripted.supervisor.invoke(scripted.run_command, token()))
    assert codes_of(failure) == (INVARIANT_VIOLATION,)
    assert scripted.controller.terminate_calls
    assert scripted.stored_invocation().state is CommandInvocationState.RUNNING


def test_a_lifecycle_failure_while_running_is_an_orchestrator_cancellation(
    scripted: _Scripted,
) -> None:
    scripted.stdout_chunks = [valid_heartbeat_line(sequence=1)]
    scripted.lifecycle.fail("append_event", CONCURRENCY_CONFLICT)
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is CommandInvocationState.CANCELLED
    assert causal_codes(primary(record)) == (CONCURRENCY_CONFLICT,)
    assert (
        scripted.stored_run().state is EngineRunState.CANCELLED
    )  # reading 8: the retriable posture is forfeited on purpose


def test_a_clean_exit_carries_no_stage_seven_diagnostic(scripted: _Scripted) -> None:
    scripted.exit_after = 1
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    assert outcome.command_result.diagnostics == ()
    assert outcome.command_result.invocation.cleanup_complete


# --------------------------------------------------------------------------
# Once-only forced termination and the external-winner census (carried notes B, E)
# --------------------------------------------------------------------------


def _cancel_on_running(
    scripted: _Scripted, cancel: ThreadSafeCancellationToken
) -> None:
    scripted.observer.on(
        RUNNING_COMMITTED, lambda _entry: cancel.request_cancellation()
    )


def _arm_grace_expiry(scripted: _Scripted, cancel: ThreadSafeCancellationToken) -> None:
    _cancel_on_running(scripted, cancel)
    scripted.advance_per_tick(1.0)


def _arm_interrupt_unavailable(
    scripted: _Scripted, cancel: ThreadSafeCancellationToken
) -> None:
    scripted.controller.interrupt_outcome = InterruptOutcome.UNAVAILABLE
    _arm_grace_expiry(scripted, cancel)


def _arm_rejection(scripted: _Scripted, _cancel: ThreadSafeCancellationToken) -> None:
    scripted.stdout_chunks = [b"not json\n"]


def _arm_pre_handoff_cancel(
    scripted: _Scripted, cancel: ThreadSafeCancellationToken
) -> None:
    scripted.controller.on_launch = cancel.request_cancellation


def _arm_pre_handoff_deadline(
    scripted: _Scripted, _cancel: ThreadSafeCancellationToken
) -> None:
    scripted.controller.on_launch = lambda: scripted.clock.advance(TIMEOUT_SECONDS + 1)


def _arm_pipe_holder_then_deadline(
    scripted: _Scripted, _cancel: ThreadSafeCancellationToken
) -> None:
    scripted.exit_after = 1
    scripted.hold_stdout_open = True
    scripted.release_on_terminate = False
    scripted.advance_per_tick(0.5)


def _arm_pipe_holder_then_flush_rejection(
    scripted: _Scripted, _cancel: ThreadSafeCancellationToken
) -> None:
    scripted.exit_after = 1
    scripted.hold_stdout_open = True
    scripted.stdout_chunks = [b'{"unterminated']
    scripted.advance_per_tick(0.5)


def _arm_external_winner_at_handoff(
    scripted: _Scripted, _cancel: ThreadSafeCancellationToken
) -> None:
    scripted.lifecycle.before(
        "record_process_start", lambda: scripted.cancel_run_externally()
    )


def _arm_external_winner_at_terminal(
    scripted: _Scripted, _cancel: ThreadSafeCancellationToken
) -> None:
    scripted.exit_after = 1
    scripted.lifecycle.before(
        "record_terminal", lambda: scripted.terminalize_invocation_externally()
    )


def _arm_own_request_defect(
    scripted: _Scripted, _cancel: ThreadSafeCancellationToken
) -> None:
    scripted.exit_after = 1
    scripted.step_utc_backwards_before("record_terminal")


def _arm_refused_terminal(
    scripted: _Scripted, _cancel: ThreadSafeCancellationToken
) -> None:
    scripted.exit_after = 1
    scripted.lifecycle.fail("record_terminal", INVARIANT_VIOLATION)


def _arm_append_failure(
    scripted: _Scripted, _cancel: ThreadSafeCancellationToken
) -> None:
    scripted.stdout_chunks = [valid_heartbeat_line(sequence=1)]
    scripted.lifecycle.fail("append_event", CONCURRENCY_CONFLICT)


def _arm_another_actor(
    scripted: _Scripted, _cancel: ThreadSafeCancellationToken
) -> None:
    scripted.lifecycle.before(
        "begin_start", lambda: scripted.start_invocation_externally()
    )


def _arm_cleanup_failure(
    scripted: _Scripted, _cancel: ThreadSafeCancellationToken
) -> None:
    scripted.exit_after = 1
    scripted.controller.close_failures = (
        CleanupFailure(action=CleanupAction.JOB_CLOSED, reason="close_failed:6"),
    )


def _arm_lost_enrichment(
    scripted: _Scripted, _cancel: ThreadSafeCancellationToken
) -> None:
    scripted.exit_after = 1
    scripted.lifecycle.fail("enrich", CONCURRENCY_CONFLICT)


def _arm_launch_failure(
    scripted: _Scripted, _cancel: ThreadSafeCancellationToken
) -> None:
    scripted.controller.launch_failure = LaunchFailure(
        stage="resume", os_error_code=5, error_class="ResumeThread", not_found=False
    )


def _arm_missed_heartbeat_then_deadline(
    scripted: _Scripted, _cancel: ThreadSafeCancellationToken
) -> None:
    scripted.stdout_chunks = [valid_heartbeat_line(sequence=1)]
    scripted.advance_per_tick(0.5)


def _arm_clean_exit(scripted: _Scripted, _cancel: ThreadSafeCancellationToken) -> None:
    scripted.exit_after = 1


Arm = Callable[[_Scripted, ThreadSafeCancellationToken], None]
#: Every path plan 6.4, 6.5 and 5.3 name as a forced-termination site (carried note B).
FORCE_PATHS: Final[dict[str, Arm]] = {
    "grace_elapsed": _arm_grace_expiry,
    "interrupt_unavailable": _arm_interrupt_unavailable,
    "protocol_failed": _arm_rejection,
    "pre_handoff_cancellation": _arm_pre_handoff_cancel,
    "pre_handoff_deadline": _arm_pre_handoff_deadline,
    "pipe_holder_then_deadline": _arm_pipe_holder_then_deadline,
    "pipe_holder_then_flush_rejection": _arm_pipe_holder_then_flush_rejection,
    "external_winner_at_handoff": _arm_external_winner_at_handoff,
    "external_winner_at_terminal": _arm_external_winner_at_terminal,
    "own_request_defect": _arm_own_request_defect,
    "refused_terminal_write": _arm_refused_terminal,
    "lifecycle_failure_while_running": _arm_append_failure,
    "another_actor_at_begin_start": _arm_another_actor,
    "cleanup_failure_after_terminal": _arm_cleanup_failure,
    "lost_enrichment_swap": _arm_lost_enrichment,
}
#: Every branch outside the begin_start/record_process_start window (carried note E).
NON_WINDOW_PATHS: Final[dict[str, Arm]] = {
    "launch_failure": _arm_launch_failure,
    "protocol_failed": _arm_rejection,
    "missed_heartbeat_then_deadline": _arm_missed_heartbeat_then_deadline,
    "cancellation": _arm_grace_expiry,
    "clean_exit": _arm_clean_exit,
    "reader_cancelled_after_pipe_holder": _arm_pipe_holder_then_deadline,
    "refused_terminal_write": _arm_refused_terminal,
    "external_winner_at_terminal": _arm_external_winner_at_terminal,
    "own_request_defect": _arm_own_request_defect,
    "cleanup_failure_after_terminal": _arm_cleanup_failure,
    "lost_enrichment_swap": _arm_lost_enrichment,
    "lifecycle_failure_while_running": _arm_append_failure,
    "another_actor_at_begin_start": _arm_another_actor,
}


@pytest.mark.parametrize("path", sorted(FORCE_PATHS))
def test_forced_termination_is_issued_at_most_once_on_every_named_path(
    scripted: _Scripted, path: str
) -> None:
    cancel = ThreadSafeCancellationToken()
    FORCE_PATHS[path](scripted, cancel)
    result = run(scripted.supervisor.invoke(scripted.run_command, cancel))
    assert len(scripted.controller.terminate_calls) <= 1, path
    assert (
        sum(1 for e in scripted.observer.entries if e.kind is FORCED_TERMINATION) <= 1
    ), path
    if isinstance(result, Success):
        codes = [d.error_code for d in result.value.command_result.diagnostics]
        assert codes.count(PROCESS_FORCED_TERMINATION) <= 1, path
        assert (
            scripted.codes_of_ids(
                result.value.command_result.invocation.diagnostic_ids
            ).count(PROCESS_FORCED_TERMINATION)
            <= 1
        ), path
    assert scripted.controller.identity_terminate_calls == []  # never by identity


@pytest.mark.parametrize("path", sorted(NON_WINDOW_PATHS))
def test_resolve_external_winner_is_never_called_outside_the_launch_window(
    scripted: _Scripted, path: str
) -> None:
    cancel = ThreadSafeCancellationToken()
    NON_WINDOW_PATHS[path](scripted, cancel)
    run(scripted.supervisor.invoke(scripted.run_command, cancel))
    assert scripted.lifecycle.calls.count("resolve_external_winner") == 0, path


def test_an_undeliverable_interrupt_records_the_limitation_and_waits_the_grace(
    scripted: _Scripted,
) -> None:
    cancel = ThreadSafeCancellationToken()
    _arm_interrupt_unavailable(scripted, cancel)
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, cancel))
    ).command_result.invocation
    codes = scripted.codes_of_ids(record.diagnostic_ids)
    assert record.state is CANCELLED
    assert PROCESS_GRACEFUL_INTERRUPT_UNAVAILABLE in codes
    assert codes.count(PROCESS_FORCED_TERMINATION) == 1
    kinds = [e.kind for e in scripted.observer.entries]
    unavailable_at = kinds.index(SupervisionTraceKind.INTERRUPT_UNAVAILABLE)
    forced_at = kinds.index(FORCED_TERMINATION)
    assert unavailable_at < forced_at  # the grace wait precedes the force
    assert (
        scripted.controller.polls_between(
            SupervisionTraceKind.INTERRUPT_UNAVAILABLE, FORCED_TERMINATION
        )
        >= 1
    )
    forced = scripted.observer.entries[forced_at]
    assert forced.facts["reason"] == "interrupt_unavailable"
    assert record.native_exit_value == FORCED_TERMINATION_EXIT_CODE


# --------------------------------------------------------------------------
# The wait bound (plan 6.3 step 9)
# --------------------------------------------------------------------------


def test_every_wait_bound_is_finite_positive_and_never_above_the_tick(
    scripted: _Scripted,
) -> None:
    scripted.stdout_chunks = [valid_heartbeat_line(sequence=1)]
    scripted.advance_per_tick(0.5)
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is TIMED_OUT
    assert scripted.wait_bounds
    for bound in scripted.wait_bounds:
        assert isinstance(bound, float)
        assert bound == bound  # the NaN self-comparison
        assert 0.0 < bound <= TICK_SECONDS
        assert str(bound) != "-0.0"


def test_a_reaped_exit_with_a_held_pipe_never_produces_a_zero_bound(
    scripted: _Scripted,
) -> None:
    # R-BOUND: after the reap the armed, unminted monitor no longer lowers the bound,
    # so a held pipe waits in ticks instead of spinning until the pipe-holder window.
    scripted.exit_after = 1
    scripted.hold_stdout_open = True
    scripted.release_on_terminate = False
    scripted.advance_per_tick(0.5)
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is TIMED_OUT
    assert scripted.wait_bounds
    assert all(0.0 < bound <= TICK_SECONDS for bound in scripted.wait_bounds)
    assert not any(e.kind is HEARTBEAT_MISSED for e in scripted.observer.entries)


def test_the_wait_bound_is_the_remaining_deadline_when_that_is_shorter(
    scripted: _Scripted,
) -> None:
    scripted.advance_per_tick(TIMEOUT_SECONDS - 0.005)  # the first poll leaves 5 ms
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is TIMED_OUT
    assert scripted.wait_bounds[0] == pytest.approx(0.005)
    assert scripted.wait_bounds[0] < TICK_SECONDS


def test_the_wait_bound_is_the_remaining_heartbeat_threshold_before_the_mint(
    scripted: _Scripted,
) -> None:
    scripted.advance_per_tick(1.995)  # the first poll leaves 5 ms of the 2 s threshold
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is TIMED_OUT
    assert scripted.wait_bounds[0] == pytest.approx(0.005)
    missed = [e for e in scripted.observer.entries if e.kind is HEARTBEAT_MISSED]
    assert len(missed) == 1


# --------------------------------------------------------------------------
# Describe counting, post-decision parsing, stderr truncation, projections
# --------------------------------------------------------------------------


def test_a_describe_counts_stdout_bytes_and_never_parses_them(
    scripted: _Scripted,
) -> None:
    scripted.stdout_chunks = [b"x", b"yz", b"!"]
    scripted.exit_after = 1
    outcome = ok(run(scripted.supervisor.invoke(scripted.describe_command, token())))
    assert outcome.command_result.invocation.state is EXITED
    assert outcome.stdout_byte_count == 4
    counted = [
        e for e in outcome.trace if e.kind is SupervisionTraceKind.STDOUT_BYTES_COUNTED
    ]
    assert len(counted) == 1
    assert counted[0].facts["stdout_byte_count"] == 4
    assert outcome.command_result.accepted_events == ()
    assert outcome.protocol_summary.accepted_count == 0
    assert not any(
        e.kind
        in (SupervisionTraceKind.EVENT_ACCEPTED, SupervisionTraceKind.EVENT_REJECTED)
        for e in scripted.observer.entries
    )
    assert outcome.command_result.protocol_integrity is ProtocolIntegrityStatus.INTACT


def test_post_decision_lines_are_parsed_and_appended_but_never_change_the_decision(
    scripted: _Scripted,
) -> None:
    cancel = ThreadSafeCancellationToken()
    scripted.hold_stdout_open = True
    _arm_grace_expiry(scripted, cancel)
    lines = [valid_heartbeat_line(sequence=1), valid_heartbeat_line(sequence=2)]
    scripted.lifecycle.before(
        "record_terminal", lambda: scripted.controller.deliver_stdout(*lines)
    )
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, cancel)))
    record = outcome.command_result.invocation
    assert record.state is CANCELLED
    assert len(outcome.command_result.accepted_events) == 2
    assert outcome.protocol_summary.accepted_count == 2
    assert scripted.lifecycle.calls.count("append_event") == 2
    assert scripted.lifecycle.calls.count("record_terminal") == 1
    accepted = [e for e in scripted.observer.entries if e.kind is EVENT_ACCEPTED]
    decided_at = [e.kind for e in scripted.observer.entries].index(TERMINAL_DECIDED)
    assert len(accepted) == 2
    assert all(
        scripted.observer.entries.index(entry) > decided_at for entry in accepted
    )


def test_a_post_decision_append_failure_stops_parsing_and_rides_the_enrichment(
    scripted: _Scripted,
) -> None:
    cancel = ThreadSafeCancellationToken()
    scripted.hold_stdout_open = True
    _arm_grace_expiry(scripted, cancel)
    lines = [valid_heartbeat_line(sequence=1), valid_heartbeat_line(sequence=2)]
    scripted.lifecycle.before(
        "record_terminal", lambda: scripted.controller.deliver_stdout(*lines)
    )
    scripted.lifecycle.fail("append_event", CONCURRENCY_CONFLICT)
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, cancel)))
    record = outcome.command_result.invocation
    assert record.state is CANCELLED
    assert scripted.stored_run().state is EngineRunState.CANCELLED
    assert CONCURRENCY_CONFLICT in scripted.codes_of_ids(record.diagnostic_ids)
    assert primary_code(record) == PROCESS_CANCELLED
    assert causal_ids(primary(record)) == ()  # the failure is additional, not causal
    assert outcome.command_result.accepted_events == ()
    assert scripted.lifecycle.calls.count("append_event") == 1  # parsing stopped
    assert scripted.lifecycle.calls.count("enrich") == 1


def test_a_post_decision_rejection_is_an_additional_diagnostic_not_a_new_decision(
    scripted: _Scripted,
) -> None:
    cancel = ThreadSafeCancellationToken()
    scripted.hold_stdout_open = True
    _arm_grace_expiry(scripted, cancel)
    scripted.lifecycle.before(
        "record_terminal", lambda: scripted.controller.deliver_stdout(b"not json\n")
    )
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, cancel)))
    record = outcome.command_result.invocation
    assert record.state is CANCELLED
    assert outcome.command_result.protocol_integrity is ProtocolIntegrityStatus.INTACT
    assert PROTOCOL_STDOUT_CONTAMINATION in scripted.codes_of_ids(record.diagnostic_ids)
    rejected = [
        e for e in outcome.trace if e.kind is SupervisionTraceKind.EVENT_REJECTED
    ]
    assert len(rejected) == 1
    assert isinstance(rejected[0].rejection, EventRejected)


def test_stderr_truncation_on_a_core_won_terminal_comes_from_the_fed_counter(
    scripted: _Scripted,
) -> None:
    scripted.stderr_chunks = [b"e" * (MIN_STDERR_BYTES + 1)]
    scripted.stdout_chunks = [b"not json\n"]
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is PROTOCOL_FAILED
    assert PROCESS_STDERR_TRUNCATED in scripted.codes_of_ids(record.diagnostic_ids)
    stderr = outcome.command_result.stderr
    assert isinstance(stderr, StderrCapture)
    assert stderr.truncated
    assert stderr.retained_byte_count == MIN_STDERR_BYTES


def test_the_retained_trace_is_ordered_bounded_and_agrees_with_the_projections(
    scripted: _Scripted,
) -> None:
    cancel = ThreadSafeCancellationToken()
    scripted.stdout_chunks = [valid_heartbeat_line(sequence=1)]
    scripted.observer.on(EVENT_ACCEPTED, lambda _entry: cancel.request_cancellation())
    scripted.advance_per_tick(1.0)
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, cancel)))
    kinds = kinds_of(outcome)
    assert kinds.index(SupervisionTraceKind.PREFLIGHT_ACCEPTED) < kinds.index(
        SupervisionTraceKind.EXECUTABLE_OBSERVED
    )
    assert kinds.index(SupervisionTraceKind.STARTING_COMMITTED) < kinds.index(
        SupervisionTraceKind.REQUEST_WRITTEN
    )
    assert kinds.index(SupervisionTraceKind.REQUEST_WRITTEN) < kinds.index(
        SupervisionTraceKind.LAUNCHED
    )
    assert kinds.index(SupervisionTraceKind.LAUNCHED) < kinds.index(RUNNING_COMMITTED)
    assert kinds.index(RUNNING_COMMITTED) < kinds.index(TERMINAL_DECIDED)
    assert kinds[-1] is ENRICHMENT_COMMITTED
    assert EVENT_ACCEPTED not in kinds  # observer-only, never retained
    assert [e.sequence for e in outcome.trace] == sorted(
        e.sequence for e in outcome.trace
    )
    assert len({e.sequence for e in outcome.trace}) == len(outcome.trace)
    result = outcome.command_result
    assert (result.cancelled, result.timed_out) == (True, False)
    assert result.protocol_integrity is ProtocolIntegrityStatus.INTACT
    assert len(result.accepted_events) == 1
    assert outcome.replay_count == 0
    assert outcome.executable_observation.verified


def test_the_supervisor_never_inspects_a_pid_or_terminates_by_identity(
    scripted: _Scripted,
) -> None:
    scripted.advance_per_tick(0.5)
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is TIMED_OUT
    assert scripted.controller.inspect_calls == []
    assert scripted.controller.identity_terminate_calls == []
    assert scripted.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]


# --------------------------------------------------------------------------
# No false EXITED and no semantic success (plan 6.4 closing paragraph)
# --------------------------------------------------------------------------


def test_a_zero_exit_without_output_is_a_process_fact_and_moves_no_run(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is EXITED
    assert record.native_exit_value == 0
    assert not isinstance(outcome.output_parse, ManifestParse)  # no file, no parse
    assert isinstance(outcome.command_result.parsed_output, type(MISSING))
    assert (
        scripted.stored_run().state is EngineRunState.RUNNING
    )  # never a success state
    assert scripted.stored_experiment().state is ExperimentState.RUNNING


def test_favorable_output_after_a_protocol_failure_is_never_read(
    scripted: _Scripted,
) -> None:
    scripted.stdout_chunks = [b"not json\n"]
    scripted.exit_after = 1
    scripted.observer.on(
        SupervisionTraceKind.REQUEST_WRITTEN,
        lambda _entry: _plant_result(scripted, b'{"favorable": true}'),
    )
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    assert outcome.command_result.invocation.state is PROTOCOL_FAILED
    assert isinstance(outcome.output_parse, type(MISSING))
    assert isinstance(outcome.command_result.parsed_output, type(MISSING))
    assert scripted.stored_run().state is EngineRunState.FAILED


def _plant_result(scripted: _Scripted, data: bytes) -> None:
    result_path = scripted.run_command.result_path
    assert isinstance(result_path, str)
    Path(result_path).parent.mkdir(parents=True, exist_ok=True)
    Path(result_path).write_bytes(data)


def test_a_failed_stdout_read_never_becomes_exited(scripted: _Scripted) -> None:
    # A lost pipe: the reader ends with the CANCELLED marker, never EOF, so a reaped
    # zero exit stays a process fact under the deadline (plan 6.4: no false EXITED).
    scripted.exit_after = 1
    scripted.controller.stdout_read_error = True
    scripted.advance_per_tick(0.5)
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is TIMED_OUT
    assert record.native_exit_value == 0  # the root's own exit, by enrichment
    stopped = next(
        e
        for e in scripted.observer.entries
        if e.kind is SupervisionTraceKind.CLEANUP_ACTION
        and e.facts["action"] == "STDOUT_READER_STOPPED"
    )
    assert stopped.facts["ended_by"] == "CANCELLED"
    assert scripted.controller.cancel_read_calls == []  # the thread had already ended


def test_a_fully_drained_exit_beats_a_cancellation_observed_in_the_same_tick(
    scripted: _Scripted,
) -> None:
    # Reading 10: X beats C. The exit is reaped on the third poll, by which time
    # both EOF markers were dequeued on the earlier ticks; the token is set inside
    # that same third poll, so both facts are observed in one tick.
    cancel = token()
    scripted.exit_after = 3

    def cancel_on_the_reaping_poll(poll: int) -> None:
        if poll == 3:
            cancel.request_cancellation()

    scripted.controller.on_poll = cancel_on_the_reaping_poll
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, cancel))
    ).command_result.invocation
    assert record.state is EXITED
    assert record.native_exit_value == 0
    assert scripted.controller.terminate_calls == []
    assert scripted.controller.interrupt_calls == 0
    assert scripted.stored_run().state is EngineRunState.RUNNING


def test_a_fully_drained_exit_beats_a_deadline_observed_in_the_same_tick(
    scripted: _Scripted,
) -> None:
    # Reading 10: X beats D. The deadline passes inside the reaping poll itself.
    scripted.exit_after = 3

    def expire_on_the_reaping_poll(poll: int) -> None:
        if poll == 3:
            scripted.clock.advance(TIMEOUT_SECONDS + 1)

    scripted.controller.on_poll = expire_on_the_reaping_poll
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is EXITED
    assert record.native_exit_value == 0
    assert scripted.controller.terminate_calls == []


def _arm_pre_handoff_cancel_with_bytes(
    scripted: _Scripted, cancel: ThreadSafeCancellationToken
) -> None:
    scripted.stdout_chunks = [valid_heartbeat_line(sequence=1)]
    scripted.controller.on_launch = cancel.request_cancellation


def _arm_pre_handoff_deadline_with_bytes(
    scripted: _Scripted, _cancel: ThreadSafeCancellationToken
) -> None:
    scripted.stdout_chunks = [valid_heartbeat_line(sequence=1)]
    scripted.controller.on_launch = lambda: scripted.clock.advance(TIMEOUT_SECONDS + 1)


def _arm_lost_handoff_with_bytes(
    scripted: _Scripted, _cancel: ThreadSafeCancellationToken
) -> None:
    scripted.stdout_chunks = [valid_heartbeat_line(sequence=1), b'{"fragment']
    scripted.lifecycle.before(
        "record_process_start", lambda: scripted.cancel_run_externally()
    )


#: Review finding B-1: a child that never reached RUNNING may still have written bytes.
STARTING_ORIGIN_WITH_BYTES: Final[dict[str, tuple[Arm, CommandInvocationState]]] = {
    "pre_handoff_cancellation": (_arm_pre_handoff_cancel_with_bytes, CANCELLED),
    "pre_handoff_deadline": (_arm_pre_handoff_deadline_with_bytes, TIMED_OUT),
    "lost_handoff_swap": (_arm_lost_handoff_with_bytes, CANCELLED),
}


@pytest.mark.parametrize("path", sorted(STARTING_ORIGIN_WITH_BYTES))
def test_bytes_from_a_child_that_never_reached_running_are_drained_not_parsed(
    scripted: _Scripted, path: str
) -> None:
    arm, expected = STARTING_ORIGIN_WITH_BYTES[path]
    cancel = ThreadSafeCancellationToken()
    arm(scripted, cancel)
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, cancel)))
    record = outcome.command_result.invocation
    assert record.state is expected, path
    assert record.process_created is False
    assert record.cleanup_complete
    assert scripted.lifecycle.calls.count("append_event") == 0
    assert scripted.lifecycle.calls.count("enrich") == 1
    assert scripted.controller.close_flags == [(True, True)]
    assert outcome.command_result.accepted_events == ()
    assert outcome.stdout_byte_count == 0
    assert not any(
        e.kind in (EVENT_ACCEPTED, SupervisionTraceKind.EVENT_REJECTED)
        for e in scripted.observer.entries
    )
    assert not Path(scripted.run_command.request_path).parent.exists()


def test_an_external_winner_over_a_created_root_without_a_child_still_cleans_up(
    scripted: _Scripted,
) -> None:
    # Review finding N-2: a STARTING-origin FAILED_TO_START write lost to an external
    # terminalization must still remove the pre-handoff root and enrich once.
    scripted.controller.launch_failure = LaunchFailure(
        stage="resume", os_error_code=5, error_class="ResumeThread", not_found=False
    )
    scripted.lifecycle.before(
        "record_terminal", lambda: scripted.terminalize_invocation_externally()
    )
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is CANCELLED  # the external winner's state, not overwritten
    assert record.process_created is False
    assert record.cleanup_complete
    assert scripted.lifecycle.calls.count("enrich") == 1
    assert not Path(scripted.run_command.request_path).parent.exists()
    assert any(
        e.kind is SupervisionTraceKind.EXTERNAL_TERMINAL_WINNER for e in outcome.trace
    )
    assert scripted.controller.terminate_calls == []  # nothing was launched


def test_stderr_is_absent_when_the_launch_window_is_lost_before_the_envelope(
    scripted: _Scripted,
) -> None:
    # Review finding N-8: the begin_start-failure rows decide before the envelope.
    scripted.lifecycle.before("begin_start", lambda: scripted.cancel_run_externally())
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    assert outcome.command_result.invocation.state is CANCELLED
    assert not isinstance(outcome.command_result.stderr, StderrCapture)


# --------------------------------------------------------------------------
# The lifecycle-failure and drain branches (plan 13 coverage floor)
# --------------------------------------------------------------------------


def test_an_identical_replay_of_an_accepted_sequence_is_counted_not_appended(
    scripted: _Scripted,
) -> None:
    line = valid_heartbeat_line(sequence=1)
    scripted.stdout_chunks = [line, line]
    scripted.exit_after = 1
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    assert outcome.command_result.invocation.state is EXITED
    assert outcome.replay_count == 1
    assert len(outcome.command_result.accepted_events) == 1
    assert scripted.lifecycle.calls.count("append_event") == 1
    replayed = [
        e
        for e in scripted.observer.entries
        if e.kind is SupervisionTraceKind.EVENT_REPLAYED
    ]
    assert len(replayed) == 1
    assert replayed[0].facts["sequence"] == 1
    assert not any(  # observer-only, like EVENT_ACCEPTED
        e.kind is SupervisionTraceKind.EVENT_REPLAYED for e in outcome.trace
    )


def test_an_unrecognized_native_exit_value_is_exited_with_its_own_primary(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    scripted.controller.exit_code = 77
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is EXITED
    assert record.native_exit_value == 77
    diagnostic = primary(record)
    assert diagnostic.error_code == PROCESS_UNRECOGNIZED_PROCESS_EXIT
    assert diagnostic.details == {"native_exit_value": 77}


def test_stderr_truncation_on_an_exited_terminal_rides_the_terminal_write(
    scripted: _Scripted,
) -> None:
    scripted.stderr_chunks = [b"e" * (MIN_STDERR_BYTES + 1)]
    scripted.exit_after = 1
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is EXITED
    assert PROCESS_STDERR_TRUNCATED in scripted.codes_of_ids(record.diagnostic_ids)
    stderr = outcome.command_result.stderr
    assert isinstance(stderr, StderrCapture)
    assert stderr.truncated


def test_stderr_truncation_rides_the_enrichment_when_the_terminal_was_not_ours(
    scripted: _Scripted,
) -> None:
    scripted.stderr_chunks = [b"e" * (MIN_STDERR_BYTES + 1)]
    scripted.exit_after = 1
    scripted.lifecycle.before(
        "record_terminal", lambda: scripted.terminalize_invocation_externally()
    )
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is CANCELLED  # the external winner's state
    assert PROCESS_STDERR_TRUNCATED in scripted.codes_of_ids(record.diagnostic_ids)
    assert scripted.lifecycle.calls.count("enrich") == 1


def test_a_terminal_written_by_another_actor_before_begin_start_is_returned(
    scripted: _Scripted,
) -> None:
    # Plan 5.3 row 1 from PENDING: nothing was launched or written, so nothing is
    # forced, removed or enriched; the stored terminal is the outcome.
    scripted.lifecycle.before(
        "begin_start", lambda: scripted.terminalize_invocation_externally()
    )
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is CANCELLED
    assert record == scripted.stored_invocation()
    assert scripted.controller.launches == ()
    assert scripted.lifecycle.calls.count("enrich") == 0
    assert "resolve_external_winner" not in scripted.lifecycle.calls
    assert any(
        e.kind is SupervisionTraceKind.EXTERNAL_TERMINAL_WINNER for e in outcome.trace
    )
    assert not isinstance(outcome.command_result.stderr, StderrCapture)


def test_a_terminal_written_by_another_actor_during_the_handoff_is_returned(
    scripted: _Scripted,
) -> None:
    # Plan 5.3 row 1 from STARTING with a child: the reload finds the terminal, so
    # `resolve_external_winner` is never called; the child is forced, the root removed.
    scripted.lifecycle.before(
        "record_process_start", lambda: scripted.terminalize_invocation_externally()
    )
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is CANCELLED
    assert record.process_created is False
    assert "resolve_external_winner" not in scripted.lifecycle.calls
    assert scripted.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    assert scripted.lifecycle.calls.count("enrich") == 1
    assert not Path(scripted.run_command.request_path).parent.exists()


def test_a_refused_external_winner_resolution_abandons_the_record(
    scripted: _Scripted,
) -> None:
    scripted.lifecycle.before(
        "record_process_start", lambda: scripted.cancel_run_externally()
    )
    scripted.lifecycle.fail("resolve_external_winner", CONCURRENCY_CONFLICT)
    result = run(scripted.supervisor.invoke(scripted.run_command, token()))
    assert isinstance(result, Failure)
    assert scripted.lifecycle.calls.count("resolve_external_winner") == 1
    assert scripted.lifecycle.calls.count("enrich") == 0
    assert scripted.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    assert scripted.stored_invocation().state is STARTING  # left for reconciliation
    assert not Path(scripted.run_command.request_path).parent.exists()


def _arm_reload_failure(scripted: _Scripted, method: str) -> None:
    """``method`` fails, and the reload that classifies the refusal fails too."""
    scripted.lifecycle.fail(method, INVARIANT_VIOLATION)
    scripted.lifecycle.before(
        method, lambda: scripted.lifecycle.fail("load", CONCURRENCY_CONFLICT)
    )


def test_a_failed_reload_after_a_refused_terminal_write_abandons_the_record(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    _arm_reload_failure(scripted, "record_terminal")
    result = run(scripted.supervisor.invoke(scripted.run_command, token()))
    assert codes_of(result) == (INVARIANT_VIOLATION,)  # the write's own failure
    assert scripted.lifecycle.calls.count("load") == 2
    assert scripted.lifecycle.calls.count("enrich") == 0
    assert scripted.stored_invocation().state is RUNNING
    assert scripted.controller.close_flags == [(True, True)]
    assert Path(scripted.run_command.request_path).parent.exists()  # owned root kept


def test_a_failed_reload_after_a_lost_handoff_abandons_and_removes_the_root(
    scripted: _Scripted,
) -> None:
    _arm_reload_failure(scripted, "record_process_start")
    result = run(scripted.supervisor.invoke(scripted.run_command, token()))
    assert codes_of(result) == (INVARIANT_VIOLATION,)
    assert scripted.lifecycle.calls.count("load") == 2
    assert "resolve_external_winner" not in scripted.lifecycle.calls
    assert scripted.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    assert scripted.stored_invocation().state is STARTING
    assert not Path(scripted.run_command.request_path).parent.exists()


def test_a_failed_reload_with_a_root_but_no_child_still_removes_the_root(
    scripted: _Scripted, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unwritable(*_args: object, **_kwargs: object) -> object:
        raise OSError(errno.EACCES, "scripted denial")

    monkeypatch.setattr(supervisor_module, "write_request_file", unwritable)
    _arm_reload_failure(scripted, "record_terminal")
    result = run(scripted.supervisor.invoke(scripted.run_command, token()))
    assert codes_of(result) == (INVARIANT_VIOLATION,)
    assert scripted.controller.launches == ()
    assert scripted.stored_invocation().state is STARTING
    assert not Path(scripted.run_command.request_path).parent.exists()


def test_an_identical_external_enrichment_is_not_an_external_winner(
    scripted: _Scripted,
) -> None:
    # The lost enrichment swap whose reload already carries everything the
    # supervisor would have written: no winner is reported (plan 5.3 last row).
    scripted.exit_after = 1

    def enrich_identically() -> None:
        current = scripted.stored_invocation()
        ok(
            scripted.lifecycle._inner.enrich(
                scripted.invocation_id,
                expected_revision=current.revision,
                native_exit_value=MISSING,
                cleanup_complete=True,
                additional=(),
            )
        )

    scripted.lifecycle.before("enrich", enrich_identically)
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is EXITED
    assert record.cleanup_complete is True
    assert scripted.lifecycle.calls.count("enrich") == 1
    assert not any(
        e.kind is SupervisionTraceKind.EXTERNAL_TERMINAL_WINNER for e in outcome.trace
    )
    assert not any(
        e.kind is SupervisionTraceKind.ENRICHMENT_COMMITTED for e in outcome.trace
    )


def test_a_lost_enrichment_whose_reload_fails_reports_the_last_known_record(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    scripted.lifecycle.fail("enrich", CONCURRENCY_CONFLICT)
    scripted.lifecycle.before(
        "enrich", lambda: scripted.lifecycle.fail("load", CONCURRENCY_CONFLICT)
    )
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is EXITED
    assert record.cleanup_complete is False  # the pre-enrichment record
    assert scripted.lifecycle.calls.count("load") == 2
    assert any(
        e.kind is SupervisionTraceKind.EXTERNAL_TERMINAL_WINNER for e in outcome.trace
    )


def test_an_exit_during_the_grace_period_hands_a_held_pipe_to_the_drain(
    scripted: _Scripted,
) -> None:
    cancel = ThreadSafeCancellationToken()
    scripted.exit_after = 3
    scripted.hold_stdout_open = True
    scripted.observer.on(
        RUNNING_COMMITTED, lambda _entry: cancel.request_cancellation()
    )
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, cancel))
    ).command_result.invocation
    assert record.state is CANCELLED
    assert scripted.controller.interrupt_calls == 1
    assert scripted.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    forced = [
        e
        for e in scripted.observer.entries
        if e.kind is SupervisionTraceKind.FORCED_TERMINATION
    ]
    assert [e.facts["reason"] for e in forced] == ["pipe_holder"]


def test_a_second_reader_that_cannot_start_leaves_no_unstarted_thread_to_stop(
    scripted: _Scripted, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_start = PipeReader.start
    starts: list[int] = []

    def start_once(self: PipeReader) -> None:
        starts.append(1)
        if len(starts) == 2:
            raise RuntimeError("scripted: no second reader thread")
        original_start(self)

    monkeypatch.setattr(PipeReader, "start", start_once)
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is FAILED_TO_START
    diagnostic = primary(record)
    assert diagnostic.details == {
        "stage": "open_readers",
        "error_class": "RuntimeError",
    }
    assert record.cleanup_complete
    assert scripted.controller.close_flags == [(True, True)]
    assert scripted.controller.cancel_read_calls == []


def test_exited_is_never_decided_before_both_pipes_end(scripted: _Scripted) -> None:
    scripted.exit_after = 1
    scripted.hold_stderr_open = True
    scripted.release_on_terminate = False
    scripted.advance_per_tick(0.5)
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert (
        record.state is TIMED_OUT
    )  # a reaped zero exit with an open pipe is not EXITED
    assert record.native_exit_value == 0  # the root's own exit, by enrichment
    stopped = next(
        e
        for e in scripted.observer.entries
        if e.kind is SupervisionTraceKind.CLEANUP_ACTION
        and e.facts["action"] == "STDERR_READER_STOPPED"
    )
    assert stopped.facts["ended_by"] == "CANCELLED"


# --------------------------------------------------------------------------
# The cross-check findings: open_readers, held diagnostics, observers, describe count
# --------------------------------------------------------------------------


def test_a_reader_that_cannot_start_is_a_launch_failure_at_stage_open_readers(
    scripted: _Scripted, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_args: object, **_kwargs: object) -> object:
        raise ValueError("no reader thread")

    monkeypatch.setattr(supervisor_module, "PipeReader", refuse)
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is FAILED_TO_START
    diagnostic = primary(record)
    assert diagnostic.error_code == PROCESS_LAUNCH_FAILED
    assert diagnostic.details == {"stage": "open_readers", "error_class": "ValueError"}
    assert scripted.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    assert scripted.controller.close_flags == [(True, True)]  # no reader blocks a pipe
    assert not Path(scripted.run_command.request_path).parent.exists()
    assert scripted.stored_run().state is EngineRunState.FAILED
    assert scripted.lifecycle.calls.count("enrich") == 1
    assert record.cleanup_complete
    assert PROCESS_FORCED_TERMINATION in scripted.codes_of_ids(record.diagnostic_ids)


def test_a_held_job_diagnostic_rides_the_external_winner_enrichment(
    scripted: _Scripted,
) -> None:
    scripted.controller.job_available = False
    scripted.controller.job_error_code = 5
    scripted.lifecycle.before(
        "record_process_start", lambda: scripted.cancel_run_externally()
    )
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is CANCELLED
    codes = scripted.codes_of_ids(record.diagnostic_ids)
    assert PROCESS_JOB_OBJECT_UNAVAILABLE in codes
    assert PROCESS_FORCED_TERMINATION in codes
    forced = [e for e in scripted.observer.entries if e.kind is FORCED_TERMINATION]
    assert forced[0].facts["reason"] == "external_winner"
    assert scripted.lifecycle.calls.count("enrich") == 1


def test_a_pipe_holder_termination_rides_the_terminal_write_before_the_enrichment(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    scripted.hold_stdout_open = True
    scripted.advance_per_tick(0.5)
    at_enrichment: list[tuple[str, ...]] = []
    scripted.lifecycle.before(
        "enrich",
        lambda: at_enrichment.append(
            scripted.codes_of_ids(scripted.stored_invocation().diagnostic_ids)
        ),
    )
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is EXITED
    (codes,) = at_enrichment
    assert PROCESS_FORCED_TERMINATION in codes  # already on the EXITED transition


def test_a_raising_observer_never_alters_the_decision(scripted: _Scripted) -> None:
    def defect(_entry: object) -> None:
        raise RuntimeError("observer defect")

    scripted.observer.on(TERMINAL_DECIDED, defect)
    scripted.exit_after = 1
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    assert outcome.command_result.invocation.state is EXITED
    assert outcome.command_result.invocation.cleanup_complete
    assert scripted.lifecycle.calls.count("enrich") == 1
    assert kinds_of(outcome)[-1] is ENRICHMENT_COMMITTED


def test_a_never_launched_describe_still_carries_one_stdout_count_entry(
    scripted: _Scripted,
) -> None:
    cancel = token()
    cancel.request_cancellation()
    outcome = ok(run(scripted.supervisor.invoke(scripted.describe_command, cancel)))
    assert outcome.command_result.invocation.state is CANCELLED
    counted = [
        e for e in outcome.trace if e.kind is SupervisionTraceKind.STDOUT_BYTES_COUNTED
    ]
    assert len(counted) == 1
    assert counted[0].facts["stdout_byte_count"] == 0
    assert outcome.stdout_byte_count == 0


def test_a_timed_out_describe_counts_every_byte_including_post_decision_ones(
    scripted: _Scripted,
) -> None:
    scripted.stdout_chunks = [b"abc"]
    scripted.hold_stdout_open = True
    scripted.advance_per_tick(0.5)
    scripted.lifecycle.before(
        "record_terminal", lambda: scripted.controller.deliver_stdout(b"de")
    )
    outcome = ok(run(scripted.supervisor.invoke(scripted.describe_command, token())))
    assert outcome.command_result.invocation.state is TIMED_OUT
    assert outcome.stdout_byte_count == 5
    counted = [
        e for e in outcome.trace if e.kind is SupervisionTraceKind.STDOUT_BYTES_COUNTED
    ]
    assert len(counted) == 1
    assert counted[0].facts["stdout_byte_count"] == 5


def test_the_supervision_state_holds_the_token_only_inside_the_envelope() -> None:
    state_fields = {f.name: f for f in fields(supervisor_module._Supervision)}
    assert "token" not in state_fields
    assert not any("attempt_token" in name for name in state_fields)
    assert state_fields["envelope"].repr is False


# --------------------------------------------------------------------------
# One real child through the Windows controller (plan Task 6, Windows-specific)
# --------------------------------------------------------------------------


def test_a_real_describe_through_the_windows_controller_reaches_exited(
    tmp_path: Path,
) -> None:
    root = tmp_path / "sup"
    root.mkdir()
    store = InMemoryBackingStore()
    clock = RealtimeMonotonicClock(_INSTANT)
    entry = supervised_catalog_entry_for(_ADAPTER_NAME)
    support = CORE_PROTOCOL_SUPPORT
    payload = DescribeRequestPayload(
        bootstrap_schema_version="1.0.0",
        adapter_name=_ADAPTER_NAME,
        adapter_version=_ADAPTER_VERSION,
        executable_hash=entry.executable_hash,
        core_supported_protocol_versions=support.protocol_versions,
        core_supported_schema_versions=support.schema_versions,
        core_capability_vocabulary_versions=support.vocabulary_versions,
    )
    invocation_id = SequentialIdentitySource("task6-real").new_invocation_id()
    store.command_invocations.live[invocation_id] = sample_invocation(
        PENDING,
        kind=CommandKind.DESCRIBE,
        invocation_id=invocation_id,
        adapter_name=_ADAPTER_NAME,
        adapter_version=_ADAPTER_VERSION,
        request_hash=request_hash_of(payload),
        timeout_seconds=30,
    )
    lifecycle = Stage5InvocationLifecycle(
        unit_of_work=InMemoryUnitOfWork(store, clock=clock),
        clock=clock,
        diagnostics=SeedingDiagnosticRecorder(store),
    )
    lifecycle.register_request_material(
        invocation_id, RequestMaterial(describe_payload=payload)
    )
    paths = plan_command_paths(
        str(root), command_kind=CommandKind.DESCRIBE, invocation_id=invocation_id
    )
    command = AdapterCommand(
        command_kind=CommandKind.DESCRIBE,
        catalog_entry=entry,
        invocation_id=invocation_id,
        request_path=paths.request_path,
        output_path=paths.output_path,
        timeout_seconds=30,
    )
    controller = WindowsProcessController()
    observer = RecordingObserver()
    supervisor = build_supervisor(
        lifecycle=lifecycle,
        controller=controller,
        clock=clock,
        supervision_root=str(root),
        observers=(observer,),
    )
    outcome = ok(run(supervisor.invoke(command, token())))
    record = outcome.command_result.invocation
    try:
        assert record.state is EXITED
        assert record.native_exit_value == 0
        assert record.cleanup_complete
        assert isinstance(outcome.output_parse, DescriptorParse)
        assert isinstance(outcome.output_parse.envelope, BootstrapDescriptorEnvelope)
        assert outcome.command_result.diagnostics == ()
        assert outcome.stdout_byte_count == 0
        identity = record.pid_identity
        assert isinstance(identity, ProcessIdentity)
        parse_creation_identity(identity.creation_identity)
        assert kinds_of(outcome)[-1] is ENRICHMENT_COMMITTED
    finally:
        identity = record.pid_identity
        if isinstance(identity, ProcessIdentity):
            if (
                controller.inspect(identity).presence is ProcessPresence.ALIVE_MATCHING
            ):  # the test-tree rule: terminate what a test launched, then assert
                controller.terminate_tree(identity, FORCED_TERMINATION_EXIT_CODE)
            assert (
                controller.inspect(identity).presence
                is not ProcessPresence.ALIVE_MATCHING
            )
