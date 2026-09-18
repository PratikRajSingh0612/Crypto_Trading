"""Stage 7 Task 5: the ``experiments`` lifecycle behind the supervision port.

Plan section 12 Task 5 over plan 3.6, 4.4, 5.1-5.4 and 9.2. The first RED of Task 5
is the ``crypto_lab.experiments.supervision_lifecycle`` and ``doubles.supervision``
imports below: the two modules the task creates. The fixture drives
``Stage5InvocationLifecycle`` over ``InMemoryBackingStore``, ``FixedClock``,
``SequentialIdentitySource`` and the merged ``sample_*`` helpers with four seeded
``PENDING`` invocations, every one at revision 0, and every seeded linked run
carrying the request hash and attempt-token hash the harness seeds.

Test-local readings, declared rather than inferred silently:

- The plan's Step 1 tests are copied verbatim except for the strict-mypy fixture
  annotation, one ``# noqa: E501`` on a definition line the formatter cannot shorten
  and the PT018 splits of the plan's compound asserts (every clause kept, in order).
- Three runs at ``attempt_number=1`` in one experiment need three selected slots
  (the merged attempt index is ``(experiment_id, logical_slot_id, attempt_number)``
  and a spec selects each adapter/engine pair once), so the fixture experiment selects
  a third slot with a third adapter identity; the VALIDATE pair sits on it.
- ``move_run`` is the merged ``transition_run`` (the harness's own external-move
  precedent) with the slot's frozen observation for ``READY`` and a freshly minted,
  recorder-seeded Stage 6 primary for a terminal target.
- ``forget_request_material`` rebuilds the fixture's lifecycle over the same store,
  clock and recorder with every registration but the forgotten one; the lifecycle
  itself exposes ``register_request_material`` and the nine port members only.
- The attempt tokens are fixed synthetic values built from expressions, never string
  literals bound to a ``_TOKEN`` name (plan 2.6), and never printed.
"""

from __future__ import annotations

import ast
import inspect
import json
import re
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any, Final

import pytest
from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

import crypto_lab.experiments as experiments_package
from contract.harness import DEFAULT_NEGOTIATED, assert_token_absent
from crypto_lab.adapters.commands import CommandResult
from crypto_lab.adapters.diagnostics import (
    ADAPTER_UNAVAILABLE,
    COMPAT_NOT_APPLICABLE,
    ENGINE_RUNTIME_FAILURE,
    PROCESS_CANCELLED,
    PROCESS_RUN_TIMED_OUT,
    PROCESS_UNRECOGNIZED_PROCESS_EXIT,
    PROCESS_VALIDATE_TIMED_OUT,
    PROTOCOL_STDOUT_CONTAMINATION,
    stage6_diagnostic,
)
from crypto_lab.adapters.envelopes import (
    DescribeRequestPayload,
    EngineRunRequest,
    request_hash_of,
    request_material_hash,
)
from crypto_lab.adapters.events import (
    EventAcceptanceContext,
    EventAccepted,
    InvocationEventLedger,
    ProtocolEventSummary,
    RunEvent,
    parse_protocol_line,
)
from crypto_lab.adapters.limits import PROTOCOL_LIMITS_DEFAULT
from crypto_lab.adapters.manifests import (
    ManifestParse,
    ValidationResultParse,
    parse_result_manifest,
    parse_validation_result,
)
from crypto_lab.adapters.negotiation import CORE_PROTOCOL_SUPPORT
from crypto_lab.adapters.vocabulary import ProtocolIntegrityStatus
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.engine_run import AttemptTokenMaterial, EngineRunRecord
from crypto_lab.domain.experiment import (
    AdapterIdentity,
    EngineIdentity,
    ExperimentRecord,
    SelectedEngineSlot,
)
from crypto_lab.domain.hashing import _uuid4_shaped, attempt_token_hash, sha256_bytes
from crypto_lab.domain.lifecycle import (
    TERMINAL_COMMAND_INVOCATION_STATES,
    TERMINAL_ENGINE_RUN_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
    ProcessExitCategory,
    process_exit_category_for,
)
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments import supervision_lifecycle as lifecycle_module
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    stage5_failure,
)
from crypto_lab.experiments.experiment_service import cancel_experiment
from crypto_lab.experiments.requests import (
    CancelExperimentRequest,
    RunTransitionRequest,
    SemanticOutcomeRequest,
)
from crypto_lab.experiments.run_service import transition_run
from crypto_lab.experiments.supervision_lifecycle import (
    SUPERVISION_REASON_CODE,
    DiagnosticRecorder,
    RequestMaterial,
    Stage5InvocationLifecycle,
    semantic_outcome_request_for,
)
from crypto_lab.process_supervision.diagnostics import (
    PROCESS_CLEANUP_FAILED,
    PROCESS_LAUNCH_FAILED,
    stage7_diagnostic,
)
from crypto_lab.process_supervision.models import RunReconciliationFacts
from crypto_lab.process_supervision.ports import (
    InvocationLifecycle,
    ReconciliationSource,
)
from doubles import supervision as doubles_module
from doubles.experiments import (
    EXECUTABLE_HASH,
    EXPERIMENT_ID,
    INSTANT,
    SLOT_A,
    SLOT_B,
    SLOT_C,
    UUID_D,
    UUID_E,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    SequentialIdentitySource,
    sample_draft,
    sample_experiment,
    sample_invocation,
    sample_process_start,
    sample_run,
    sample_slots,
)
from doubles.supervision import InMemoryReconciliationSource, SeedingDiagnosticRecorder

_INSTANT: Final = INSTANT
#: The seeded experiment and runs were created a minute before the clock, so their
#: sample ``updated_at_utc`` (creation plus one second per revision) never lies after
#: the instant the merged bookkeeping rule stamps on the first swap.
_SEEDED_AT: Final = INSTANT - timedelta(seconds=60)
_SUPERVISOR: Final = "process_supervision.supervisor"
FAILED_TO_START: Final = CommandInvocationState.FAILED_TO_START
CANCELLED: Final = CommandInvocationState.CANCELLED
TIMED_OUT: Final = CommandInvocationState.TIMED_OUT
PROTOCOL_FAILED: Final = CommandInvocationState.PROTOCOL_FAILED
EXITED: Final = CommandInvocationState.EXITED
RUNNING: Final = CommandInvocationState.RUNNING
PENDING: Final = CommandInvocationState.PENDING
STARTING: Final = CommandInvocationState.STARTING
#: The third selected slot the fixture needs (module docstring).
_THIRD_ADAPTER: Final = AdapterIdentity(
    adapter_name="adapter.gamma", adapter_version="1.0.0"
)
_THIRD_ENGINE: Final = EngineIdentity(
    engine_name="engine.gamma", engine_version="2.3.4"
)
#: Fixed synthetic attempt material per slot, built from expressions (plan 2.6).
_MATERIAL_BY_SLOT: Final[dict[str, str]] = {
    SLOT_A: "k" * 32,
    SLOT_B: "m" * 32,
    SLOT_C: "n" * 32,
}
#: The nine members of the port, plan 3.4.
_PORT_MEMBERS: Final = (
    "load",
    "linked_run",
    "begin_start",
    "request_envelope",
    "record_process_start",
    "record_terminal",
    "enrich",
    "append_event",
    "resolve_external_winner",
)
#: Names Tasks 6-8 own; none may appear in the Task 5 lifecycle module.
_LATER_TASK_NAMES: Final = (
    "WindowsProcessSupervisor",
    "reconcile_invocations",
    "RecordingLifecycle",
    "RecordingObserver",
    "ScriptedProcess",
    "ScriptedProcessController",
    "SupervisionFixedClock",
    "RealtimeMonotonicClock",
    "TeeController",
    "build_supervisor",
    "supervised_catalog_entry_for",
)
#: Stage 7 Task 6 defined exactly these nine in `tests/doubles/supervision.py` (plan
#: 9.2); Task 8 added `TeeController` there, and `reconcile_invocations` (Task 7) is
#: a production function that never joins the doubles.
_TASK6_DOUBLES_NAMES: Final = (
    "WindowsProcessSupervisor",
    "RecordingLifecycle",
    "RecordingObserver",
    "ScriptedProcess",
    "ScriptedProcessController",
    "SupervisionFixedClock",
    "RealtimeMonotonicClock",
    "build_supervisor",
    "supervised_catalog_entry_for",
)
_TASK8_DOUBLES_NAMES: Final = ("TeeController",)
_NON_SUCCESS_RUN_STATES: Final = TERMINAL_ENGINE_RUN_STATES - {
    EngineRunState.SUCCEEDED,
    EngineRunState.SUCCEEDED_WITH_WARNINGS,
}
#: The Stage 6 primary ``move_run`` mints for an external terminal run target.
_RUN_PRIMARY_CODE: Final[dict[EngineRunState, str]] = {
    EngineRunState.CANCELLED: PROCESS_CANCELLED,
    EngineRunState.TIMED_OUT: PROCESS_RUN_TIMED_OUT,
    EngineRunState.FAILED: ENGINE_RUNTIME_FAILURE,
    EngineRunState.NOT_APPLICABLE: COMPAT_NOT_APPLICABLE,
    EngineRunState.UNAVAILABLE: ADAPTER_UNAVAILABLE,
}
_ERROR_CODE_SHAPE: Final = re.compile(r"[A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)+")


# --------------------------------------------------------------------------
# Helpers (``ok`` and ``codes_of`` as in Task 3)
# --------------------------------------------------------------------------


def codes_of(result: object) -> tuple[str, ...]:
    assert isinstance(result, Failure), result
    return tuple(diagnostic.error_code for diagnostic in result.diagnostics)


def ok[T](result: Success[T] | Failure) -> T:
    assert isinstance(result, Success), result
    return result.value


def _public_members(port: type) -> set[str]:
    # the merged tests/unit/domain/test_domain_ports.py helper skips properties (not
    # callable); this one keeps them
    return {
        name
        for name, value in vars(port).items()
        if not name.startswith("_") and (callable(value) or isinstance(value, property))
    }


def _conforms_lifecycle(lifecycle: InvocationLifecycle) -> InvocationLifecycle:
    """A static conformance probe: the class satisfies the port structurally."""
    return lifecycle


def _conforms_recorder(recorder: DiagnosticRecorder) -> DiagnosticRecorder:
    return recorder


def _conforms_source(source: ReconciliationSource) -> ReconciliationSource:
    return source


_LIFECYCLE_PROBE: Final[Callable[[Stage5InvocationLifecycle], InvocationLifecycle]] = (
    _conforms_lifecycle
)
_RECORDER_PROBE: Final[Callable[[SeedingDiagnosticRecorder], DiagnosticRecorder]] = (
    _conforms_recorder
)
_SOURCE_PROBE: Final[Callable[[InMemoryReconciliationSource], ReconciliationSource]] = (
    _conforms_source
)


def _target_ids(source: InMemoryReconciliationSource) -> list[str]:
    return [record.invocation_id for record in ok(source.list_reconciliation_targets())]


def _is_target(record: CommandInvocationRecord) -> bool:
    terminal = record.state in TERMINAL_COMMAND_INVOCATION_STATES
    return not terminal or not record.cleanup_complete


class _RefusingRecorder:
    """A recorder whose every ``record`` is a ``Failure``; it seeds nothing."""

    def record(self, diagnostic: Diagnostic) -> Result[None]:
        del diagnostic
        return stage5_failure(
            INVARIANT_VIOLATION,
            "the recorder refused",
            source_component="task5.refusing_recorder",
            timestamp_utc=_INSTANT,
        )


# --------------------------------------------------------------------------
# The fixture
# --------------------------------------------------------------------------


class _Fixture:
    """The plan Task 5 fixture: one experiment, three runs, four invocations."""

    def __init__(self) -> None:
        self.store = InMemoryBackingStore()
        self.clock = FixedClock(_INSTANT)
        self.identity = SequentialIdentitySource("task5")
        self.unit_of_work = InMemoryUnitOfWork(self.store, clock=self.clock)
        self.recorder = SeedingDiagnosticRecorder(self.store)
        self.experiment_id = EXPERIMENT_ID
        draft = sample_draft(
            selected_engine_slots=(
                *sample_slots(),
                SelectedEngineSlot(
                    logical_slot_id=SLOT_C,
                    slot_ordinal=2,
                    adapter=_THIRD_ADAPTER,
                    engine=_THIRD_ENGINE,
                ),
            )
        )
        experiment = sample_experiment(
            ExperimentState.RUNNING, draft=draft, created_at_utc=_SEEDED_AT
        )
        self.store.experiments.live[experiment.experiment_id] = experiment
        self.run = self._seed_run(SLOT_A, EngineRunState.READY)
        self.run_kind_run = self._seed_run(SLOT_B, EngineRunState.READY)
        self.validate_kind_run = self._seed_run(SLOT_C, EngineRunState.VALIDATING)
        self.slot_observation_id = self._frozen_observation(SLOT_C)
        self.inv = self._seed_invocation(CommandKind.RUN, self.run)
        self.run_kind_inv = self._seed_invocation(CommandKind.RUN, self.run_kind_run)
        self.validate_kind_inv = self._seed_invocation(
            CommandKind.VALIDATE, self.validate_kind_run
        )
        support = CORE_PROTOCOL_SUPPORT
        self.describe_payload = DescribeRequestPayload(
            bootstrap_schema_version="1.0.0",
            adapter_name="adapter.alpha",
            adapter_version="1.0.0",
            executable_hash=EXECUTABLE_HASH,
            core_supported_protocol_versions=support.protocol_versions,
            core_supported_schema_versions=support.schema_versions,
            core_capability_vocabulary_versions=support.vocabulary_versions,
        )
        self.describe_inv = self._seed_describe_invocation()
        self._run_of: dict[str, str] = {
            self.inv: self.run,
            self.run_kind_inv: self.run_kind_run,
            self.validate_kind_inv: self.validate_kind_run,
        }
        self._invocation_of: dict[str, str] = {
            run_id: invocation_id for invocation_id, run_id in self._run_of.items()
        }
        self.token_material = self.token_material_for(
            self.run, attempt_token=_MATERIAL_BY_SLOT[SLOT_A]
        )
        self._materials: dict[str, RequestMaterial] = {
            self.inv: self._linked_material(self.run, SLOT_A),
            self.run_kind_inv: self._linked_material(self.run_kind_run, SLOT_B),
            self.validate_kind_inv: self._linked_material(
                self.validate_kind_run, SLOT_C
            ),
            self.describe_inv: RequestMaterial(describe_payload=self.describe_payload),
        }
        self.lifecycle = self._build_lifecycle()

    # -- Seeding ------------------------------------------------------------------

    def stored_experiment(self) -> ExperimentRecord:
        return self.store.experiments.live[self.experiment_id]

    def _frozen_observation(self, logical_slot_id: str) -> str:
        compatibility = self.stored_experiment().slot_compatibility
        assert isinstance(compatibility, tuple)
        (entry,) = (
            item for item in compatibility if item.logical_slot_id == logical_slot_id
        )
        return entry.availability_observation_id

    def _seed_run(self, logical_slot_id: str, state: EngineRunState) -> str:
        experiment = self.stored_experiment()
        (slot,) = (
            item
            for item in experiment.spec.selected_engine_slots
            if item.logical_slot_id == logical_slot_id
        )
        run_id = self.identity.new_run_id()
        record = sample_run(
            state,
            run_id=run_id,
            experiment_id=experiment.experiment_id,
            logical_slot_id=logical_slot_id,
            adapter=slot.adapter,
            engine=slot.engine,
            request_hash=request_material_hash(
                experiment=experiment,
                logical_slot_id=logical_slot_id,
                attempt_number=1,
                negotiated=DEFAULT_NEGOTIATED,
                limits=PROTOCOL_LIMITS_DEFAULT,
            ),
            attempt_token=_MATERIAL_BY_SLOT[logical_slot_id],
            availability_observation_id=self._frozen_observation(logical_slot_id),
            created_at_utc=_SEEDED_AT,
        )
        self.store.engine_runs.live[run_id] = record
        return run_id

    def _seed_invocation(self, kind: CommandKind, run_id: str) -> str:
        run = self.stored_run(run_id)
        invocation_id = self.identity.new_invocation_id()
        record = sample_invocation(
            PENDING,
            kind=kind,
            invocation_id=invocation_id,
            run_id=run_id,
            adapter_name=run.adapter.adapter_name,
            adapter_version=run.adapter.adapter_version,
            request_hash=run.request_hash,
        )
        self.store.command_invocations.live[invocation_id] = record
        return invocation_id

    def _seed_describe_invocation(self) -> str:
        invocation_id = self.identity.new_invocation_id()
        record = sample_invocation(
            PENDING,
            kind=CommandKind.DESCRIBE,
            invocation_id=invocation_id,
            adapter_name=self.describe_payload.adapter_name,
            adapter_version=self.describe_payload.adapter_version,
            request_hash=request_hash_of(self.describe_payload),
        )
        self.store.command_invocations.live[invocation_id] = record
        return invocation_id

    def _linked_material(self, run_id: str, logical_slot_id: str) -> RequestMaterial:
        return RequestMaterial(
            token=self.token_material_for(
                run_id, attempt_token=_MATERIAL_BY_SLOT[logical_slot_id]
            ),
            negotiated_versions=DEFAULT_NEGOTIATED,
            limits=PROTOCOL_LIMITS_DEFAULT,
        )

    def _build_lifecycle(self) -> Stage5InvocationLifecycle:
        lifecycle = Stage5InvocationLifecycle(
            unit_of_work=self.unit_of_work,
            clock=self.clock,
            diagnostics=self.recorder,
        )
        for invocation_id, material in self._materials.items():
            lifecycle.register_request_material(invocation_id, material)
        return lifecycle

    # -- The plan's fixture helpers ------------------------------------------------

    def token_material_for(
        self, run_id: str, *, attempt_token: str
    ) -> AttemptTokenMaterial:
        return AttemptTokenMaterial(run_id=run_id, attempt_token=attempt_token)

    def forget_request_material(self, invocation_id: str) -> None:
        del self._materials[invocation_id]
        self.lifecycle = self._build_lifecycle()

    def stored_run(self, run_id: object = None) -> EngineRunRecord:
        key = self.run if run_id is None else run_id
        assert isinstance(key, str)
        return self.store.engine_runs.live[key]

    def stored_invocation(self, invocation_id: str) -> CommandInvocationRecord:
        return self.store.command_invocations.live[invocation_id]

    def running(self, invocation_id: str) -> CommandInvocationRecord:
        ok(self.lifecycle.begin_start(invocation_id, expected_revision=0))
        return ok(
            self.lifecycle.record_process_start(
                invocation_id, expected_revision=1, process_start=sample_process_start()
            )
        )

    def terminal(
        self, invocation_id: str, state: CommandInvocationState
    ) -> CommandInvocationRecord:
        self.running(invocation_id)
        kind = self.stored_invocation(invocation_id).command_kind
        timeout_code = (
            PROCESS_VALIDATE_TIMED_OUT
            if kind is CommandKind.VALIDATE
            else PROCESS_RUN_TIMED_OUT
        )
        code = {
            CANCELLED: PROCESS_CANCELLED,
            TIMED_OUT: timeout_code,
            PROTOCOL_FAILED: PROTOCOL_STDOUT_CONTAMINATION,
        }[state]
        return ok(
            self.lifecycle.record_terminal(
                invocation_id,
                expected_revision=2,
                target_state=state,
                primary=self.mint_stage6(code, invocation_id=invocation_id),
                additional=(),
                native_exit_value=MISSING,
            )
        )

    def move_run(
        self, state: EngineRunState, *, run_id: object = None
    ) -> EngineRunRecord:
        """An external ``transition_run`` (module docstring)."""
        key = self.run if run_id is None else run_id
        assert isinstance(key, str)
        run = self.stored_run(key)
        payload: dict[str, object] = {
            "schema_version": "1.0.0",
            "run_id": key,
            "expected_revision": run.revision,
            "target_state": state,
            "reason_code": "TASK5.EXTERNAL_MOVE",
        }
        if state in (EngineRunState.READY, EngineRunState.UNAVAILABLE):
            payload["availability_observation_id"] = self._frozen_observation(
                run.logical_slot_id
            )
        if state in _NON_SUCCESS_RUN_STATES:
            primary = self.mint_stage6(
                _RUN_PRIMARY_CODE[state], invocation_id=self._invocation_of[key]
            )
            ok(self.recorder.record(primary))
            payload["primary_terminal_diagnostic_id"] = primary.diagnostic_id
        return ok(
            transition_run(
                RunTransitionRequest.model_validate(payload),
                unit_of_work=self.unit_of_work,
                clock=self.clock,
            )
        )

    def cancel_experiment(self) -> ExperimentRecord:
        return ok(
            cancel_experiment(
                CancelExperimentRequest(
                    schema_version="1.0.0",
                    experiment_id=self.experiment_id,
                    expected_revision=self.stored_experiment().revision,
                    correlation_id="task5-cancel",
                ),
                unit_of_work=self.unit_of_work,
                clock=self.clock,
            )
        )

    def _mint(
        self,
        factory: Callable[..., Diagnostic],
        code: str,
        invocation_id: str | None,
    ) -> Diagnostic:
        invocation = self.inv if invocation_id is None else invocation_id
        run_id = self._run_of.get(invocation)
        if run_id is None:
            return factory(
                code,
                "task5 diagnostic",
                source_component=_SUPERVISOR,
                timestamp_utc=self.clock.now_utc(),
                invocation_id=invocation,
            )
        return factory(
            code,
            "task5 diagnostic",
            source_component=_SUPERVISOR,
            timestamp_utc=self.clock.now_utc(),
            experiment_id=self.experiment_id,
            run_id=run_id,
            invocation_id=invocation,
        )

    def mint(self, code: str, *, invocation_id: str | None = None) -> Diagnostic:
        """A Stage 7 code through ``stage7_diagnostic``, correlated to the invocation
        and, for a linked kind, its run and experiment."""
        return self._mint(stage7_diagnostic, code, invocation_id)

    def mint_stage6(self, code: str, *, invocation_id: str | None = None) -> Diagnostic:
        """A Stage 6 code through ``stage6_diagnostic``, correlated the same way."""
        return self._mint(stage6_diagnostic, code, invocation_id)

    # -- Test-local helpers -----------------------------------------------------------

    def heartbeat_event(self, *, activity_counter: int = 1) -> RunEvent:
        """One accepted heartbeat of ``inv`` while it is ``RUNNING``; a different
        ``activity_counter`` is another content under the same sequence."""
        invocation = self.stored_invocation(self.inv)
        document: dict[str, Any] = {
            "schema_version": "1.0.0",
            "protocol_version": "1.0.0",
            "event_id": f"evt_{_uuid4_shaped(sha256_bytes(b'task5:heartbeat:1'))}",
            "invocation_id": self.inv,
            "run_id": self.run,
            "attempt_token": _MATERIAL_BY_SLOT[SLOT_A],
            "sequence": 1,
            "event_type": "HEARTBEAT",
            "timestamp_utc": "2026-09-07T11:59:59Z",
            "payload": {"activity_counter": activity_counter, "phase": "warmup"},
        }
        line = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        outcome = parse_protocol_line(
            line + b"\n",
            acceptance=EventAcceptanceContext(
                invocation=invocation,
                attempt_token_hash=attempt_token_hash(_MATERIAL_BY_SLOT[SLOT_A]),
                max_event_bytes=PROTOCOL_LIMITS_DEFAULT.max_event_bytes,
                ledger=InvocationEventLedger(),
                clock=self.clock,
            ),
        )
        assert isinstance(outcome, EventAccepted), outcome
        return outcome.event

    def every_record(self) -> tuple[object, ...]:
        """Every committed record and every seeded diagnostic, for the token walk."""
        return (
            *self.store.committed_command_invocations(),
            *self.store.committed_engine_runs(),
            *self.store.committed_experiments(),
            *self.store.committed_run_events(),
            *self.store.diagnostics.live.values(),
        )


@pytest.fixture
def fixture() -> _Fixture:
    return _Fixture()


# --------------------------------------------------------------------------
# The plan's Step 1 tests, verbatim
# --------------------------------------------------------------------------


def test_begin_start_uses_the_linked_launch_for_run_and_the_plain_transition_otherwise(
    fixture: _Fixture,
) -> None:
    started = ok(fixture.lifecycle.begin_start(fixture.inv, expected_revision=0))
    assert started.state is CommandInvocationState.STARTING
    assert (
        fixture.stored_run().state is EngineRunState.STARTING
    )  # READY -> STARTING coupled
    validate = ok(
        fixture.lifecycle.begin_start(fixture.validate_kind_inv, expected_revision=0)
    )
    assert fixture.stored_run(validate.run_id).state is EngineRunState.VALIDATING


def test_linked_run_returns_the_run_record_for_linked_kinds_only(
    fixture: _Fixture,
) -> None:
    linked = ok(fixture.lifecycle.linked_run(fixture.inv))
    assert isinstance(
        linked, EngineRunRecord
    )  # narrows EngineRunRecord | MISSING for strict mypy
    assert (linked.run_id, linked.experiment_id, linked.state) == (
        fixture.run,
        fixture.stored_run().experiment_id,
        EngineRunState.READY,
    )
    assert not isinstance(
        ok(fixture.lifecycle.linked_run(fixture.describe_inv)), EngineRunRecord
    )  # MISSING for a describe


def test_begin_start_refuses_disagreeing_or_missing_material_before_the_swap(
    fixture: _Fixture,
) -> None:
    fixture.forget_request_material(fixture.run_kind_inv)
    assert codes_of(
        fixture.lifecycle.begin_start(fixture.run_kind_inv, expected_revision=0)
    ) == (INVARIANT_VIOLATION,)  # nothing registered
    fixture.lifecycle.register_request_material(
        fixture.run_kind_inv,
        RequestMaterial(
            token=fixture.token_material_for(
                fixture.run_kind_run, attempt_token="B" * 32
            ),  # grammar-valid, not the run's
            negotiated_versions=DEFAULT_NEGOTIATED,
            limits=PROTOCOL_LIMITS_DEFAULT,
        ),
    )
    assert codes_of(
        fixture.lifecycle.begin_start(fixture.run_kind_inv, expected_revision=0)
    ) == (INVARIANT_VIOLATION,)  # token hash disagrees
    assert (
        fixture.stored_invocation(fixture.run_kind_inv).state,
        fixture.stored_run(fixture.run_kind_run).state,
    ) == (CommandInvocationState.PENDING, EngineRunState.READY)


def test_begin_start_refuses_a_cancelled_parent_before_the_swap(
    fixture: _Fixture,
) -> None:
    fixture.cancel_experiment()
    assert codes_of(
        fixture.lifecycle.begin_start(fixture.inv, expected_revision=0)
    ) == (INVARIANT_VIOLATION,)
    assert (
        fixture.stored_invocation(fixture.inv).state,
        fixture.stored_run().state,
    ) == (CommandInvocationState.PENDING, EngineRunState.READY)


def test_begin_start_refuses_a_validate_whose_run_is_not_validating(
    fixture: _Fixture,
) -> None:
    fixture.move_run(EngineRunState.NOT_APPLICABLE, run_id=fixture.validate_kind_run)
    assert codes_of(
        fixture.lifecycle.begin_start(fixture.validate_kind_inv, expected_revision=0)
    ) == (INVARIANT_VIOLATION,)


def test_resolve_external_winner_cancels_only_beside_a_terminal_run_or_cancelled_experiment(  # noqa: E501
    fixture: _Fixture,
) -> None:
    primary = fixture.mint_stage6(
        PROCESS_CANCELLED, invocation_id=fixture.validate_kind_inv
    )
    fixture.move_run(
        EngineRunState.READY, run_id=fixture.validate_kind_run
    )  # a lawful orchestrator move, not a winner
    assert not isinstance(
        ok(
            fixture.lifecycle.resolve_external_winner(
                fixture.validate_kind_inv, expected_revision=0, primary=primary
            )
        ),
        CommandInvocationRecord,
    )  # MISSING: not a winner
    assert (
        fixture.stored_run(fixture.validate_kind_run).state is EngineRunState.READY
    )  # nothing was written
    fixture.move_run(EngineRunState.CANCELLED, run_id=fixture.validate_kind_run)
    record = ok(
        fixture.lifecycle.resolve_external_winner(
            fixture.validate_kind_inv, expected_revision=0, primary=primary
        )
    )
    # split from the plan's compound assert (PT018); every clause kept, in order:
    # the alone path beside the terminal run
    assert isinstance(record, CommandInvocationRecord)
    assert record.state is CommandInvocationState.CANCELLED
    fixture.cancel_experiment()
    primary = fixture.mint_stage6(PROCESS_CANCELLED, invocation_id=fixture.run_kind_inv)
    record = ok(
        fixture.lifecycle.resolve_external_winner(
            fixture.run_kind_inv, expected_revision=0, primary=primary
        )
    )
    assert isinstance(record, CommandInvocationRecord)
    assert record.state is CommandInvocationState.CANCELLED
    assert fixture.stored_run(fixture.run_kind_run).state is EngineRunState.CANCELLED


def test_request_envelope_is_a_pure_function_of_the_starting_record_and_material(
    fixture: _Fixture,
) -> None:
    fixture.lifecycle.register_request_material(
        fixture.inv,
        RequestMaterial(
            token=fixture.token_material,
            negotiated_versions=DEFAULT_NEGOTIATED,
            limits=PROTOCOL_LIMITS_DEFAULT,
        ),
    )
    started = ok(fixture.lifecycle.begin_start(fixture.inv, expected_revision=0))
    first = ok(fixture.lifecycle.request_envelope(fixture.inv))
    second = ok(fixture.lifecycle.request_envelope(fixture.inv))
    # split from the plan's compound assert (PT018); every clause kept, in order
    assert first == second
    assert first.created_at_utc == started.launch_attempted_at_utc


@pytest.mark.parametrize(
    ("target", "run_target"),
    [
        (CommandInvocationState.CANCELLED, EngineRunState.CANCELLED),
        (CommandInvocationState.TIMED_OUT, EngineRunState.TIMED_OUT),
        (CommandInvocationState.PROTOCOL_FAILED, EngineRunState.FAILED),
    ],
)
def test_a_core_won_terminal_couples_the_run_and_records_the_primary_first(
    fixture: _Fixture, target: CommandInvocationState, run_target: EngineRunState
) -> None:
    fixture.running(fixture.inv)
    primary = fixture.mint_stage6(PROCESS_CANCELLED)
    record = ok(
        fixture.lifecycle.record_terminal(
            fixture.inv,
            expected_revision=2,
            target_state=target,
            primary=primary,
            additional=(),
            native_exit_value=MISSING,
        )
    )
    assert record.state is target
    # split from the plan's compound assert (PT018); every clause kept, in order
    assert fixture.stored_run().state is run_target
    assert fixture.stored_run().primary_terminal_diagnostic_id == primary.diagnostic_id
    assert fixture.recorder.calls[0] == primary.diagnostic_id


def test_a_terminal_beside_a_terminal_run_takes_the_alone_path(
    fixture: _Fixture,
) -> None:
    fixture.running(fixture.inv)
    fixture.move_run(EngineRunState.CANCELLED)  # transition_run won
    record = ok(
        fixture.lifecycle.record_terminal(
            fixture.inv,
            expected_revision=2,
            target_state=CommandInvocationState.CANCELLED,
            primary=fixture.mint_stage6(PROCESS_CANCELLED),
            additional=(),
            native_exit_value=MISSING,
        )
    )
    # split from the plan's compound assert (PT018); every clause kept, in order
    assert record.state is CommandInvocationState.CANCELLED
    assert fixture.stored_run().state is EngineRunState.CANCELLED


def test_an_exited_write_beside_a_run_cancelled_externally_succeeds_alone(
    fixture: _Fixture,
) -> None:
    fixture.running(fixture.inv)
    fixture.move_run(
        EngineRunState.CANCELLED
    )  # reading 17: the live path writes the decided state
    record = ok(
        fixture.lifecycle.record_terminal(
            fixture.inv,
            expected_revision=2,
            target_state=CommandInvocationState.EXITED,
            primary=MISSING,
            additional=(),
            native_exit_value=0,
        )
    )
    # split from the plan's compound assert (PT018); every clause kept, in order
    assert record.state is CommandInvocationState.EXITED
    assert fixture.stored_run().state is EngineRunState.CANCELLED


def test_failed_to_start_maps_the_run_by_the_recorded_primary_category(
    fixture: _Fixture,
) -> None:
    for invocation in (fixture.inv, fixture.run_kind_inv, fixture.validate_kind_inv):
        ok(
            fixture.lifecycle.begin_start(invocation, expected_revision=0)
        )  # STARTING beside STARTING / VALIDATING
    runtime = fixture.mint(PROCESS_LAUNCH_FAILED)  # ENGINE_RUNTIME
    ok(
        fixture.lifecycle.record_terminal(
            fixture.inv,
            expected_revision=1,
            target_state=FAILED_TO_START,
            primary=runtime,
            additional=(),
            native_exit_value=MISSING,
        )
    )
    assert fixture.stored_run().state is EngineRunState.FAILED
    availability = fixture.mint_stage6(
        ADAPTER_UNAVAILABLE, invocation_id=fixture.run_kind_inv
    )  # the merged mapping's other branch
    ok(
        fixture.lifecycle.record_terminal(
            fixture.run_kind_inv,
            expected_revision=1,
            target_state=FAILED_TO_START,
            primary=availability,
            additional=(),
            native_exit_value=MISSING,
        )
    )
    assert (
        fixture.stored_run(fixture.run_kind_run).state is EngineRunState.UNAVAILABLE
    )  # READY-time observation carried
    validate_availability = fixture.mint_stage6(
        ADAPTER_UNAVAILABLE, invocation_id=fixture.validate_kind_inv
    )
    ok(
        fixture.lifecycle.record_terminal(
            fixture.validate_kind_inv,
            expected_revision=1,
            target_state=FAILED_TO_START,
            primary=validate_availability,
            additional=(),
            native_exit_value=MISSING,
        )
    )
    validate_run = fixture.stored_run(fixture.validate_kind_run)
    assert validate_run.state is EngineRunState.UNAVAILABLE
    assert (
        validate_run.availability_observation_id == fixture.slot_observation_id
    )  # read from slot_compatibility


def test_the_recorder_is_idempotent_on_identity(fixture: _Fixture) -> None:
    diagnostic = fixture.mint(PROCESS_CLEANUP_FAILED)
    # split from the plan's compound assert (PT018); every clause kept, in order
    assert ok(fixture.recorder.record(diagnostic)) is None
    assert ok(fixture.recorder.record(diagnostic)) is None
    assert fixture.store.diagnostics.live[diagnostic.diagnostic_id] == diagnostic
    assert fixture.recorder.calls == [diagnostic.diagnostic_id] * 2


def test_enrich_writes_once_and_refuses_an_overwrite(fixture: _Fixture) -> None:
    fixture.terminal(
        fixture.inv, CommandInvocationState.TIMED_OUT
    )  # a core-won terminal at revision 3 admits an exit pair
    enriched = ok(
        fixture.lifecycle.enrich(
            fixture.inv,
            expected_revision=3,
            native_exit_value=1067,
            cleanup_complete=True,
            additional=(),
        )
    )
    # split from the plan's compound assert (PT018); every clause kept, in order
    assert enriched.native_exit_value == 1067
    assert enriched.cleanup_complete
    assert codes_of(
        fixture.lifecycle.enrich(
            fixture.inv,
            expected_revision=4,
            native_exit_value=0,
            cleanup_complete=False,
            additional=(),
        )
    ) == (INVARIANT_VIOLATION,)


# --------------------------------------------------------------------------
# Surface: exact names, exact signatures, exact consumed interfaces
# --------------------------------------------------------------------------


def test_the_module_defines_exactly_the_task_five_surface() -> None:
    classes = {
        name
        for name, value in vars(lifecycle_module).items()
        if inspect.isclass(value) and value.__module__ == lifecycle_module.__name__
    }
    functions = {
        name
        for name, value in vars(lifecycle_module).items()
        if inspect.isfunction(value)
        and value.__module__ == lifecycle_module.__name__
        and not name.startswith("_")
    }
    assert classes == {
        "DiagnosticRecorder",
        "RequestMaterial",
        "Stage5InvocationLifecycle",
    }
    assert functions == {"semantic_outcome_request_for"}
    assert SUPERVISION_REASON_CODE == "SUPERVISION.TRANSITION"
    assert lifecycle_module.SOURCE_COMPONENT == "experiments.supervision_lifecycle"
    for name in _LATER_TASK_NAMES:
        assert not hasattr(lifecycle_module, name), name
    for name in (*_TASK6_DOUBLES_NAMES, *_TASK8_DOUBLES_NAMES):
        assert hasattr(doubles_module, name), name
    for name in (
        set(_LATER_TASK_NAMES) - set(_TASK6_DOUBLES_NAMES) - set(_TASK8_DOUBLES_NAMES)
    ):
        assert not hasattr(doubles_module, name), name


def test_the_lifecycle_matches_every_port_member_signature() -> None:
    assert _public_members(Stage5InvocationLifecycle) == {
        *_PORT_MEMBERS,
        "register_request_material",
    }
    for name in _PORT_MEMBERS:
        port = inspect.signature(getattr(InvocationLifecycle, name))
        implementation = inspect.signature(getattr(Stage5InvocationLifecycle, name))
        assert [
            (parameter.name, parameter.kind, parameter.annotation)
            for parameter in implementation.parameters.values()
        ] == [
            (parameter.name, parameter.kind, parameter.annotation)
            for parameter in port.parameters.values()
        ], name
        assert implementation.return_annotation == port.return_annotation, name
    assert _public_members(DiagnosticRecorder) == {"record"}
    record = inspect.signature(DiagnosticRecorder.record)
    assert list(record.parameters) == ["self", "diagnostic"]
    helper = inspect.signature(semantic_outcome_request_for)
    assert list(helper.parameters) == [
        "command_result",
        "output_parse",
        "protocol_summary",
        "run",
        "candidate_observations",
        "negotiated_versions",
    ]
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in helper.parameters.values()
    )


def test_the_lifecycle_and_the_doubles_satisfy_their_ports(fixture: _Fixture) -> None:
    assert isinstance(fixture.lifecycle, InvocationLifecycle)
    assert isinstance(fixture.recorder, DiagnosticRecorder)
    source = InMemoryReconciliationSource(fixture.store)
    assert isinstance(source, ReconciliationSource)
    assert not isinstance(object(), DiagnosticRecorder)
    assert _LIFECYCLE_PROBE(fixture.lifecycle) is fixture.lifecycle
    assert _RECORDER_PROBE(fixture.recorder) is fixture.recorder
    assert _SOURCE_PROBE(source) is source


def test_the_recorder_implements_record_only(fixture: _Fixture) -> None:
    assert _public_members(SeedingDiagnosticRecorder) == {"record"}
    assert not hasattr(SeedingDiagnosticRecorder, "get")
    assert not hasattr(SeedingDiagnosticRecorder, "get_many")
    assert fixture.recorder.calls == []


def test_the_package_exports_the_task_five_surface_sorted() -> None:
    exported = experiments_package.__all__
    assert {
        "SUPERVISION_REASON_CODE",
        "DiagnosticRecorder",
        "RequestMaterial",
        "Stage5InvocationLifecycle",
        "semantic_outcome_request_for",
    } <= set(exported)
    assert len(set(exported)) == len(exported)
    constants = [name for name in exported if name.isupper()]
    classes = [name for name in exported if not name.isupper() and name[0].isupper()]
    functions = [name for name in exported if name[0].islower()]
    assert list(exported) == [*constants, *classes, *functions]
    for group in (constants, classes, functions):
        assert group == sorted(group)
    assert experiments_package.Stage5InvocationLifecycle is Stage5InvocationLifecycle


def test_the_module_imports_no_process_supervision_name_and_mints_one_code() -> None:
    source_path = lifecycle_module.__file__
    assert source_path is not None
    tree = ast.parse(Path(source_path).read_text(encoding="utf-8"))
    imported: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.setdefault(node.module, set()).update(
                alias.name for alias in node.names
            )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imported.setdefault(alias.name, set())
    assert not any(
        name.startswith("crypto_lab.process_supervision") for name in imported
    )
    assert not any(name.split(".")[0] in {"doubles", "tests"} for name in imported)
    assert imported["crypto_lab.experiments.diagnostics"] == {
        "INVARIANT_VIOLATION",
        "stage5_failure",
    }
    codes = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and _ERROR_CODE_SHAPE.fullmatch(node.value)
    }
    assert codes == {SUPERVISION_REASON_CODE}


def test_the_guards_name_the_new_module() -> None:
    tests_root = Path(__file__).resolve().parents[2]
    stage3 = (tests_root / "safety" / "test_stage3_boundaries.py").read_text(
        encoding="utf-8"
    )
    layout = (tests_root / "unit" / "test_package_layout.py").read_text(
        encoding="utf-8"
    )
    assert '    "experiments/supervision_lifecycle.py",\n' in stage3
    assert '    "crypto_lab.experiments.supervision_lifecycle",\n' in layout


# --------------------------------------------------------------------------
# Request material
# --------------------------------------------------------------------------


def test_request_material_is_exactly_one_shape_and_hides_the_token(
    fixture: _Fixture,
) -> None:
    with pytest.raises(ValidationError, match="exactly one"):
        RequestMaterial()
    with pytest.raises(ValidationError, match="exactly one"):
        RequestMaterial(
            describe_payload=fixture.describe_payload,
            token=fixture.token_material,
            negotiated_versions=DEFAULT_NEGOTIATED,
            limits=PROTOCOL_LIMITS_DEFAULT,
        )
    with pytest.raises(ValidationError, match="exactly one"):
        RequestMaterial(token=fixture.token_material, limits=PROTOCOL_LIMITS_DEFAULT)
    with pytest.raises(ValidationError, match="exactly one"):
        RequestMaterial(
            token=fixture.token_material, negotiated_versions=DEFAULT_NEGOTIATED
        )
    material = RequestMaterial(
        token=fixture.token_material,
        negotiated_versions=DEFAULT_NEGOTIATED,
        limits=PROTOCOL_LIMITS_DEFAULT,
    )
    assert _MATERIAL_BY_SLOT[SLOT_A] not in repr(material)
    assert _MATERIAL_BY_SLOT[SLOT_A] not in str(material)
    assert isinstance(material.token, AttemptTokenMaterial)
    describe = RequestMaterial(describe_payload=fixture.describe_payload)
    assert not isinstance(describe.token, AttemptTokenMaterial)


# --------------------------------------------------------------------------
# Lifecycle behaviour beyond the plan's block
# --------------------------------------------------------------------------


def test_load_returns_the_stored_record_and_refuses_an_unknown_identity(
    fixture: _Fixture,
) -> None:
    assert ok(fixture.lifecycle.load(fixture.inv)) == fixture.stored_invocation(
        fixture.inv
    )
    assert codes_of(fixture.lifecycle.load(f"inv_{UUID_E}")) == (INVARIANT_VIOLATION,)
    assert codes_of(fixture.lifecycle.linked_run(f"inv_{UUID_E}")) == (
        INVARIANT_VIOLATION,
    )


def test_begin_start_replays_at_the_expected_revision_and_conflicts_otherwise(
    fixture: _Fixture,
) -> None:
    started = ok(fixture.lifecycle.begin_start(fixture.inv, expected_revision=0))
    assert started.revision == 1
    # (STARTING, STARTING) replay through begin_linked_launch
    assert (
        ok(fixture.lifecycle.begin_start(fixture.inv, expected_revision=1)) == started
    )
    assert codes_of(
        fixture.lifecycle.begin_start(fixture.inv, expected_revision=0)
    ) == (CONCURRENCY_CONFLICT,)
    validate = ok(
        fixture.lifecycle.begin_start(fixture.validate_kind_inv, expected_revision=0)
    )
    replayed = ok(
        fixture.lifecycle.begin_start(fixture.validate_kind_inv, expected_revision=1)
    )
    assert replayed == validate  # same-state replay through transition_invocation
    assert fixture.stored_run(fixture.validate_kind_run).revision == 1  # untouched


def test_begin_start_refuses_a_describe_whose_payload_hash_disagrees(
    fixture: _Fixture,
) -> None:
    other = fixture.describe_payload.model_copy(update={"executable_hash": "f" * 64})
    fixture.lifecycle.register_request_material(
        fixture.describe_inv, RequestMaterial(describe_payload=other)
    )
    assert codes_of(
        fixture.lifecycle.begin_start(fixture.describe_inv, expected_revision=0)
    ) == (INVARIANT_VIOLATION,)
    assert fixture.stored_invocation(fixture.describe_inv).state is PENDING
    fixture.lifecycle.register_request_material(
        fixture.describe_inv, RequestMaterial(describe_payload=fixture.describe_payload)
    )
    started = ok(
        fixture.lifecycle.begin_start(fixture.describe_inv, expected_revision=0)
    )
    assert started.state is STARTING
    envelope = ok(fixture.lifecycle.request_envelope(fixture.describe_inv))
    assert envelope.payload == fixture.describe_payload
    assert envelope.invocation_id == fixture.describe_inv


def test_record_process_start_moves_every_kind_and_replays_identical_facts(
    fixture: _Fixture,
) -> None:
    facts = sample_process_start()
    for invocation in (fixture.describe_inv, fixture.validate_kind_inv, fixture.inv):
        ok(fixture.lifecycle.begin_start(invocation, expected_revision=0))
    for invocation in (fixture.describe_inv, fixture.validate_kind_inv, fixture.inv):
        record = ok(
            fixture.lifecycle.record_process_start(
                invocation, expected_revision=1, process_start=facts
            )
        )
        assert record.state is RUNNING
        assert record.pid_identity == facts.pid_identity
        assert record.revision == 2
    assert fixture.stored_run().state is EngineRunState.RUNNING  # the linked start
    validate_run = fixture.stored_run(fixture.validate_kind_run)
    assert validate_run.state is EngineRunState.VALIDATING
    replayed = ok(
        fixture.lifecycle.record_process_start(
            fixture.inv, expected_revision=2, process_start=facts
        )
    )
    assert replayed == fixture.stored_invocation(fixture.inv)  # identical facts replay
    divergent = fixture.lifecycle.record_process_start(
        fixture.inv,
        expected_revision=2,
        process_start=sample_process_start(pid=4322),
    )
    assert codes_of(divergent) == (CONCURRENCY_CONFLICT,)  # divergent facts conflict


def test_record_terminal_requires_a_primary_for_every_non_exited_target(
    fixture: _Fixture,
) -> None:
    fixture.running(fixture.inv)
    for target in (CANCELLED, TIMED_OUT, PROTOCOL_FAILED):
        assert codes_of(
            fixture.lifecycle.record_terminal(
                fixture.inv,
                expected_revision=2,
                target_state=target,
                primary=MISSING,
                additional=(),
                native_exit_value=MISSING,
            )
        ) == (INVARIANT_VIOLATION,)
    assert fixture.stored_invocation(fixture.inv).state is RUNNING
    assert fixture.stored_run().state is EngineRunState.RUNNING
    assert fixture.recorder.calls == []


def test_an_exited_write_carries_the_exit_pair_and_the_unrecognized_primary(
    fixture: _Fixture,
) -> None:
    fixture.running(fixture.inv)
    exited = ok(
        fixture.lifecycle.record_terminal(
            fixture.inv,
            expected_revision=2,
            target_state=EXITED,
            primary=MISSING,
            additional=(),
            native_exit_value=0,
        )
    )
    assert exited.state is EXITED
    assert exited.native_exit_value == 0
    assert exited.process_exit_category is ProcessExitCategory.SUCCESS
    assert not isinstance(exited.primary_diagnostic_id, str)
    # EXITED couples nothing
    assert fixture.stored_run().state is EngineRunState.RUNNING
    fixture.running(fixture.run_kind_inv)
    primary = fixture.mint_stage6(
        PROCESS_UNRECOGNIZED_PROCESS_EXIT, invocation_id=fixture.run_kind_inv
    )
    unrecognized = ok(
        fixture.lifecycle.record_terminal(
            fixture.run_kind_inv,
            expected_revision=2,
            target_state=EXITED,
            primary=primary,
            additional=(),
            native_exit_value=1067,
        )
    )
    assert unrecognized.primary_diagnostic_id == primary.diagnostic_id
    assert unrecognized.process_exit_category is ProcessExitCategory.RUNTIME_FAILURE
    assert fixture.recorder.calls[-1] == primary.diagnostic_id
    fixture.running(fixture.validate_kind_inv)
    assert codes_of(
        fixture.lifecycle.record_terminal(
            fixture.validate_kind_inv,
            expected_revision=2,
            target_state=EXITED,
            primary=MISSING,
            additional=(),
            native_exit_value=1067,
        )
    ) == (INVARIANT_VIOLATION,)  # the merged operation demands the primary


def test_a_recognized_exit_records_a_supplied_primary_without_promoting_it(
    fixture: _Fixture,
) -> None:
    """Plan 5.1: an ``EXITED`` write carries ``PROCESS.UNRECOGNIZED_PROCESS_EXIT`` as
    its primary only for a value outside the eight; a diagnostic handed beside a
    recognized value is recorded and joins ``diagnostic_ids`` but is not promoted."""
    fixture.running(fixture.inv)
    supplied = fixture.mint(PROCESS_CLEANUP_FAILED)
    record = ok(
        fixture.lifecycle.record_terminal(
            fixture.inv,
            expected_revision=2,
            target_state=EXITED,
            primary=supplied,
            additional=(),
            native_exit_value=50,
        )
    )
    assert record.state is EXITED
    assert record.diagnostic_ids == (supplied.diagnostic_id,)
    assert not isinstance(record.primary_diagnostic_id, str)
    assert fixture.recorder.calls == [supplied.diagnostic_id]


def test_a_validate_terminal_couples_or_stands_alone_by_the_reloaded_run_state(
    fixture: _Fixture,
) -> None:
    fixture.running(fixture.validate_kind_inv)
    primary = fixture.mint_stage6(
        PROCESS_VALIDATE_TIMED_OUT, invocation_id=fixture.validate_kind_inv
    )
    record = ok(
        fixture.lifecycle.record_terminal(
            fixture.validate_kind_inv,
            expected_revision=2,
            target_state=TIMED_OUT,
            primary=primary,
            additional=(),
            native_exit_value=MISSING,
        )
    )
    assert record.state is TIMED_OUT
    run = fixture.stored_run(fixture.validate_kind_run)
    assert run.state is EngineRunState.TIMED_OUT  # VALIDATING -> TIMED_OUT coupled
    assert run.primary_terminal_diagnostic_id == primary.diagnostic_id
    fixture.running(fixture.inv)
    fixture.move_run(EngineRunState.TIMED_OUT)  # an external transition_run won
    alone = ok(
        fixture.lifecycle.record_terminal(
            fixture.inv,
            expected_revision=2,
            target_state=PROTOCOL_FAILED,
            primary=fixture.mint_stage6(PROTOCOL_STDOUT_CONTAMINATION),
            additional=(),
            native_exit_value=MISSING,
        )
    )
    assert alone.state is PROTOCOL_FAILED
    # the run stays as the core left it
    assert fixture.stored_run().state is EngineRunState.TIMED_OUT


def test_a_recorder_failure_stops_the_terminal_write_before_the_swap(
    fixture: _Fixture,
) -> None:
    fixture.running(fixture.inv)
    refusing = Stage5InvocationLifecycle(
        unit_of_work=fixture.unit_of_work,
        clock=fixture.clock,
        diagnostics=_RefusingRecorder(),
    )
    primary = fixture.mint_stage6(PROCESS_CANCELLED)
    result = refusing.record_terminal(
        fixture.inv,
        expected_revision=2,
        target_state=CANCELLED,
        primary=primary,
        additional=(),
        native_exit_value=MISSING,
    )
    assert codes_of(result) == (INVARIANT_VIOLATION,)
    assert isinstance(result, Failure)
    assert result.diagnostics[0].source_component == "task5.refusing_recorder"
    assert fixture.stored_invocation(fixture.inv).state is RUNNING
    assert fixture.stored_run().state is EngineRunState.RUNNING
    assert primary.diagnostic_id not in fixture.store.diagnostics.live


def test_the_material_is_dropped_at_the_terminal_write(fixture: _Fixture) -> None:
    fixture.terminal(fixture.inv, CANCELLED)
    refused = fixture.lifecycle.request_envelope(fixture.inv)
    assert codes_of(refused) == (INVARIANT_VIOLATION,)
    assert isinstance(refused, Failure)
    assert refused.diagnostics[0].details == {"check": "material_missing"}
    fixture.move_run(EngineRunState.CANCELLED, run_id=fixture.run_kind_run)
    record = ok(
        fixture.lifecycle.resolve_external_winner(
            fixture.run_kind_inv,
            expected_revision=0,
            primary=fixture.mint_stage6(
                PROCESS_CANCELLED, invocation_id=fixture.run_kind_inv
            ),
        )
    )
    assert isinstance(record, CommandInvocationRecord)
    assert record.state is CANCELLED
    refused = fixture.lifecycle.request_envelope(fixture.run_kind_inv)
    assert codes_of(refused) == (INVARIANT_VIOLATION,)
    assert isinstance(refused, Failure)
    assert refused.diagnostics[0].details == {"check": "material_missing"}


def test_enrich_records_additionals_and_filters_ids_already_on_the_record(
    fixture: _Fixture,
) -> None:
    record = fixture.terminal(fixture.inv, CANCELLED)
    primary_id = record.primary_diagnostic_id
    assert isinstance(primary_id, str)
    primary = fixture.store.diagnostics.live[primary_id]
    extra = fixture.mint(PROCESS_CLEANUP_FAILED)
    enriched = ok(
        fixture.lifecycle.enrich(
            fixture.inv,
            expected_revision=3,
            native_exit_value=MISSING,
            cleanup_complete=True,
            additional=(primary, extra),
        )
    )
    assert enriched.diagnostic_ids == tuple(sorted({primary_id, extra.diagnostic_id}))
    assert enriched.cleanup_complete
    assert fixture.recorder.calls[-2:] == [primary_id, extra.diagnostic_id]
    assert codes_of(
        fixture.lifecycle.enrich(
            fixture.inv,
            expected_revision=4,
            native_exit_value=MISSING,
            cleanup_complete=False,
            additional=(primary,),
        )
    ) == (INVARIANT_VIOLATION,)  # nothing new: the merged predicate refuses


def test_append_event_commits_once_and_replays_an_identical_event(
    fixture: _Fixture,
) -> None:
    fixture.running(fixture.inv)
    event = fixture.heartbeat_event()
    assert ok(fixture.lifecycle.append_event(event)) == event
    assert ok(fixture.lifecycle.append_event(event)) == event  # idempotent
    assert fixture.store.committed_run_events() == (event,)
    assert not fixture.unit_of_work.active


def test_resolve_external_winner_returns_missing_for_a_describe(
    fixture: _Fixture,
) -> None:
    primary = fixture.mint_stage6(PROCESS_CANCELLED, invocation_id=fixture.describe_inv)
    assert not isinstance(
        ok(
            fixture.lifecycle.resolve_external_winner(
                fixture.describe_inv, expected_revision=0, primary=primary
            )
        ),
        CommandInvocationRecord,
    )
    assert fixture.stored_invocation(fixture.describe_inv).state is PENDING
    assert fixture.recorder.calls == []


def test_every_lifecycle_refusal_is_one_correlated_invariant_violation(
    fixture: _Fixture,
) -> None:
    fixture.forget_request_material(fixture.run_kind_inv)
    refused = fixture.lifecycle.begin_start(fixture.run_kind_inv, expected_revision=0)
    assert isinstance(refused, Failure)
    (diagnostic,) = refused.diagnostics
    assert diagnostic.error_code == INVARIANT_VIOLATION
    assert diagnostic.source_component == lifecycle_module.SOURCE_COMPONENT
    assert (diagnostic.experiment_id, diagnostic.run_id, diagnostic.invocation_id) == (
        fixture.experiment_id,
        fixture.run_kind_run,
        fixture.run_kind_inv,
    )
    assert diagnostic.details == {"check": "material_missing"}
    fixture.forget_request_material(fixture.describe_inv)
    refused = fixture.lifecycle.begin_start(fixture.describe_inv, expected_revision=0)
    assert isinstance(refused, Failure)
    (diagnostic,) = refused.diagnostics
    assert diagnostic.invocation_id == fixture.describe_inv
    assert not isinstance(diagnostic.run_id, str)
    assert diagnostic.details == {"check": "material_missing"}


def test_the_raw_token_never_reaches_a_record_a_diagnostic_or_a_refusal(
    fixture: _Fixture,
) -> None:
    started = ok(fixture.lifecycle.begin_start(fixture.inv, expected_revision=0))
    envelope = ok(fixture.lifecycle.request_envelope(fixture.inv))
    assert isinstance(envelope.payload, EngineRunRequest)
    assert envelope.payload.attempt_token == _MATERIAL_BY_SLOT[SLOT_A]  # wire only
    fixture.lifecycle.register_request_material(
        fixture.run_kind_inv,
        RequestMaterial(
            token=fixture.token_material_for(
                fixture.run_kind_run, attempt_token=_MATERIAL_BY_SLOT[SLOT_A]
            ),
            negotiated_versions=DEFAULT_NEGOTIATED,
            limits=PROTOCOL_LIMITS_DEFAULT,
        ),
    )
    refused = fixture.lifecycle.begin_start(fixture.run_kind_inv, expected_revision=0)
    assert codes_of(refused) == (INVARIANT_VIOLATION,)
    ok(
        fixture.lifecycle.record_process_start(
            fixture.inv, expected_revision=1, process_start=sample_process_start()
        )
    )
    ok(fixture.lifecycle.append_event(fixture.heartbeat_event()))
    fixture.terminal(fixture.validate_kind_inv, TIMED_OUT)
    objects = (
        *fixture.every_record(),
        started,
        refused,
        envelope.model_dump(mode="json", exclude={"payload"}),
    )
    for token in _MATERIAL_BY_SLOT.values():
        assert_token_absent(objects, token)
        assert token not in repr(fixture.token_material)
        assert token not in repr(fixture.lifecycle)


# --------------------------------------------------------------------------
# Refusal pins: every closed ``check`` word the lifecycle can emit, one branch each.
# Characterization tests, written after the branches existed (no RED preceded them);
# together with the tests above they pin the complete Task 5-emitted diagnostic set.
# --------------------------------------------------------------------------


def _check_of(result: object) -> str:
    assert isinstance(result, Failure), result
    (diagnostic,) = result.diagnostics
    assert diagnostic.error_code == INVARIANT_VIOLATION
    assert diagnostic.source_component == lifecycle_module.SOURCE_COMPONENT
    check = diagnostic.details["check"]
    assert isinstance(check, str)
    return check


def _linked_material_with(
    fixture: _Fixture, *, run_id: str, attempt_token: str, limits: object = None
) -> RequestMaterial:
    return RequestMaterial(
        token=fixture.token_material_for(run_id, attempt_token=attempt_token),
        negotiated_versions=DEFAULT_NEGOTIATED,
        limits=PROTOCOL_LIMITS_DEFAULT if limits is None else limits,
    )


def test_begin_start_names_each_material_disagreement_it_refuses(
    fixture: _Fixture,
) -> None:
    describe_shaped = RequestMaterial(describe_payload=fixture.describe_payload)
    fixture.lifecycle.register_request_material(fixture.inv, describe_shaped)
    refused = fixture.lifecycle.begin_start(fixture.inv, expected_revision=0)
    assert _check_of(refused) == "token_material_missing"
    fixture.lifecycle.register_request_material(
        fixture.describe_inv,
        _linked_material_with(
            fixture, run_id=fixture.run, attempt_token=_MATERIAL_BY_SLOT[SLOT_A]
        ),
    )
    refused = fixture.lifecycle.begin_start(fixture.describe_inv, expected_revision=0)
    assert _check_of(refused) == "describe_payload_missing"
    fixture.lifecycle.register_request_material(
        fixture.inv,
        _linked_material_with(
            fixture,
            run_id=fixture.run_kind_run,
            attempt_token=_MATERIAL_BY_SLOT[SLOT_A],
        ),
    )
    refused = fixture.lifecycle.begin_start(fixture.inv, expected_revision=0)
    assert _check_of(refused) == "token_run"
    other_limits = PROTOCOL_LIMITS_DEFAULT.model_copy(
        update={"heartbeat_interval_seconds": 1, "missing_heartbeat_seconds": 2}
    )
    fixture.lifecycle.register_request_material(
        fixture.inv,
        _linked_material_with(
            fixture,
            run_id=fixture.run,
            attempt_token=_MATERIAL_BY_SLOT[SLOT_A],
            limits=other_limits,
        ),
    )
    refused = fixture.lifecycle.begin_start(fixture.inv, expected_revision=0)
    assert _check_of(refused) == "request_material"  # the builder refuses the digest
    stale_hash = sample_invocation(
        PENDING,
        kind=CommandKind.RUN,
        invocation_id=f"inv_{UUID_D}",
        run_id=fixture.run,
        request_hash="9" * 64,
    )
    fixture.store.command_invocations.live[stale_hash.invocation_id] = stale_hash
    fixture.lifecycle.register_request_material(
        stale_hash.invocation_id,
        _linked_material_with(
            fixture, run_id=fixture.run, attempt_token=_MATERIAL_BY_SLOT[SLOT_A]
        ),
    )
    refused = fixture.lifecycle.begin_start(
        stale_hash.invocation_id, expected_revision=0
    )
    assert _check_of(refused) == "request_hash"
    assert fixture.stored_invocation(fixture.inv).state is PENDING
    assert fixture.stored_invocation(fixture.describe_inv).state is PENDING
    assert fixture.stored_run().state is EngineRunState.READY


def test_begin_start_reports_a_missing_run_or_experiment_as_the_repository_does(
    fixture: _Fixture,
) -> None:
    orphan = sample_invocation(
        PENDING,
        kind=CommandKind.RUN,
        invocation_id=f"inv_{UUID_D}",
        run_id=f"run_{UUID_D}",
        request_hash=fixture.stored_run().request_hash,
    )
    fixture.store.command_invocations.live[orphan.invocation_id] = orphan
    assert codes_of(
        fixture.lifecycle.begin_start(orphan.invocation_id, expected_revision=0)
    ) == (INVARIANT_VIOLATION,)
    assert codes_of(fixture.lifecycle.linked_run(orphan.invocation_id)) == (
        INVARIANT_VIOLATION,
    )
    fixture.store.engine_runs.live[f"run_{UUID_D}"] = sample_run(
        EngineRunState.READY,
        run_id=f"run_{UUID_D}",
        experiment_id=f"exp_{UUID_D}",
        created_at_utc=_SEEDED_AT,
    )
    # review F4: plan 5.1 row 13 reads the invocation and the run only
    assert ok(fixture.lifecycle.linked_run(orphan.invocation_id)) == fixture.stored_run(
        f"run_{UUID_D}"
    )
    assert codes_of(
        fixture.lifecycle.begin_start(orphan.invocation_id, expected_revision=0)
    ) == (INVARIANT_VIOLATION,)  # the run's experiment is not committed


def test_request_envelope_names_each_refusal(fixture: _Fixture) -> None:
    refused = fixture.lifecycle.request_envelope(fixture.inv)
    assert _check_of(refused) == "record_not_starting"  # still PENDING
    ok(fixture.lifecycle.begin_start(fixture.inv, expected_revision=0))
    ok(fixture.lifecycle.begin_start(fixture.describe_inv, expected_revision=0))
    fixture.lifecycle.register_request_material(
        fixture.inv, RequestMaterial(describe_payload=fixture.describe_payload)
    )
    refused = fixture.lifecycle.request_envelope(fixture.inv)
    assert _check_of(refused) == "token_material_missing"
    fixture.lifecycle.register_request_material(
        fixture.describe_inv,
        _linked_material_with(
            fixture, run_id=fixture.run, attempt_token=_MATERIAL_BY_SLOT[SLOT_A]
        ),
    )
    refused = fixture.lifecycle.request_envelope(fixture.describe_inv)
    assert _check_of(refused) == "describe_payload_missing"
    fixture.lifecycle.register_request_material(
        fixture.inv,
        _linked_material_with(
            fixture,
            run_id=fixture.run_kind_run,
            attempt_token=_MATERIAL_BY_SLOT[SLOT_B],
        ),
    )
    refused = fixture.lifecycle.request_envelope(fixture.inv)
    assert _check_of(refused) == "envelope"  # the builder refuses another run's token
    other = fixture.describe_payload.model_copy(update={"executable_hash": "f" * 64})
    fixture.lifecycle.register_request_material(
        fixture.describe_inv, RequestMaterial(describe_payload=other)
    )
    refused = fixture.lifecycle.request_envelope(fixture.describe_inv)
    assert _check_of(refused) == "envelope"  # the builder refuses the describe hash


def test_record_terminal_names_an_edge_it_cannot_couple_and_a_missing_slot(
    fixture: _Fixture,
) -> None:
    ok(fixture.lifecycle.begin_start(fixture.inv, expected_revision=0))
    refused = fixture.lifecycle.record_terminal(
        fixture.inv,
        expected_revision=1,
        target_state=PROTOCOL_FAILED,  # STARTING -> PROTOCOL_FAILED is no edge
        primary=fixture.mint_stage6(PROTOCOL_STDOUT_CONTAMINATION),
        additional=(),
        native_exit_value=MISSING,
    )
    assert _check_of(refused) == "coupled_target"
    assert fixture.stored_invocation(fixture.inv).state is STARTING
    assert fixture.recorder.calls == []  # review F2: a refusal records nothing
    unselected_run = sample_run(
        EngineRunState.VALIDATING,
        run_id=f"run_{UUID_D}",
        logical_slot_id=f"slot_{UUID_D}",
        adapter=_THIRD_ADAPTER,
        engine=_THIRD_ENGINE,
        created_at_utc=_SEEDED_AT,
    )
    fixture.store.engine_runs.live[unselected_run.run_id] = unselected_run
    unselected = sample_invocation(
        STARTING,
        kind=CommandKind.VALIDATE,
        invocation_id=f"inv_{UUID_D}",
        run_id=unselected_run.run_id,
        adapter_name=_THIRD_ADAPTER.adapter_name,
        adapter_version=_THIRD_ADAPTER.adapter_version,
        request_hash=unselected_run.request_hash,
        created_at_utc=_SEEDED_AT,
    )
    fixture.store.command_invocations.live[unselected.invocation_id] = unselected
    primary = stage6_diagnostic(
        ADAPTER_UNAVAILABLE,
        "task5 diagnostic",
        source_component=_SUPERVISOR,
        timestamp_utc=fixture.clock.now_utc(),
        experiment_id=fixture.experiment_id,
        run_id=unselected_run.run_id,
        invocation_id=unselected.invocation_id,
    )
    refused = fixture.lifecycle.record_terminal(
        unselected.invocation_id,
        expected_revision=unselected.revision,
        target_state=FAILED_TO_START,
        primary=primary,
        additional=(),
        native_exit_value=MISSING,
    )
    assert _check_of(refused) == "slot_observation_missing"
    assert fixture.stored_run(unselected_run.run_id).state is EngineRunState.VALIDATING
    assert fixture.recorder.calls == []


def test_record_terminal_refuses_a_foreign_target_before_recording(
    fixture: _Fixture,
) -> None:
    # review F6: a target that is no CommandInvocationState is a TypeError for
    # every kind, raised before the recorder or the material is touched
    fixture.running(fixture.inv)
    fixture.running(fixture.describe_inv)
    for invocation_id in (fixture.inv, fixture.describe_inv):
        with pytest.raises(TypeError, match="CommandInvocationState"):
            fixture.lifecycle.record_terminal(
                invocation_id,
                expected_revision=2,
                target_state=EngineRunState.CANCELLED,  # type: ignore[arg-type]
                primary=fixture.mint_stage6(
                    PROCESS_CANCELLED, invocation_id=invocation_id
                ),
                additional=(),
                native_exit_value=MISSING,
            )
        assert fixture.stored_invocation(invocation_id).state is RUNNING
    assert fixture.recorder.calls == []


def test_an_unrepresentable_request_is_a_refusal_not_an_exception(
    fixture: _Fixture,
) -> None:
    # review F1: the linked launch and start requests refuse like the plain ones
    refused = fixture.lifecycle.begin_start(fixture.inv, expected_revision=-1)
    assert _check_of(refused) == "request_shape"  # the linked launch request
    refused = fixture.lifecycle.begin_start(
        fixture.validate_kind_inv, expected_revision=-1
    )
    assert _check_of(refused) == "request_shape"  # the plain request, same word
    ok(fixture.lifecycle.begin_start(fixture.inv, expected_revision=0))
    refused = fixture.lifecycle.record_process_start(
        fixture.inv, expected_revision=-1, process_start=sample_process_start()
    )
    assert _check_of(refused) == "request_shape"  # the linked start request
    ok(fixture.lifecycle.begin_start(fixture.describe_inv, expected_revision=0))
    refused = fixture.lifecycle.record_process_start(
        fixture.describe_inv, expected_revision=-1, process_start=sample_process_start()
    )
    assert _check_of(refused) == "request_shape"  # the plain start request
    ok(
        fixture.lifecycle.record_process_start(
            fixture.inv, expected_revision=1, process_start=sample_process_start()
        )
    )
    crowd = tuple(
        stage6_diagnostic(
            PROCESS_CANCELLED,
            "task5 diagnostic",
            source_component=_SUPERVISOR,
            timestamp_utc=fixture.clock.now_utc(),
            experiment_id=fixture.experiment_id,
            run_id=fixture.run,
            invocation_id=fixture.inv,
            details={"ordinal": index},
        )
        for index in range(65)
    )
    assert len({diagnostic.diagnostic_id for diagnostic in crowd}) == 65
    primary = fixture.mint_stage6(PROCESS_CANCELLED)
    refused = fixture.lifecycle.record_terminal(
        fixture.inv,
        expected_revision=2,
        target_state=CANCELLED,
        primary=primary,
        additional=crowd,
        native_exit_value=MISSING,
    )
    assert _check_of(refused) == "request_shape"  # 66 ids: the coupled request
    refused = fixture.lifecycle.record_terminal(
        fixture.inv,
        expected_revision=2,
        target_state=EXITED,
        primary=MISSING,
        additional=crowd,
        native_exit_value=0,
    )
    assert _check_of(refused) == "request_shape"  # 65 ids: the plain request
    assert fixture.stored_invocation(fixture.inv).state is RUNNING
    assert fixture.recorder.calls == []  # review F2: a refusal records nothing
    fixture.move_run(EngineRunState.CANCELLED)
    refused = fixture.lifecycle.record_terminal(
        fixture.inv,
        expected_revision=2,
        target_state=CANCELLED,
        primary=primary,
        additional=crowd,
        native_exit_value=MISSING,
    )
    assert _check_of(refused) == "request_shape"  # 66 ids: the alone request
    assert len(fixture.recorder.calls) == 1  # move_run's own primary only
    ok(
        fixture.lifecycle.record_terminal(
            fixture.inv,
            expected_revision=2,
            target_state=CANCELLED,
            primary=primary,
            additional=(),
            native_exit_value=MISSING,
        )
    )
    recorded_before = list(fixture.recorder.calls)
    assert recorded_before[-1] == primary.diagnostic_id
    refused = fixture.lifecycle.enrich(
        fixture.inv,
        expected_revision=3,
        native_exit_value=MISSING,
        cleanup_complete=True,
        additional=crowd,
    )
    assert _check_of(refused) == "request_shape"  # the enrichment request
    assert fixture.recorder.calls == recorded_before


def test_every_member_reports_an_unknown_invocation_as_the_repository_does(
    fixture: _Fixture,
) -> None:
    unknown = f"inv_{UUID_E}"
    primary = fixture.mint_stage6(PROCESS_CANCELLED)
    results = (
        fixture.lifecycle.load(unknown),
        fixture.lifecycle.linked_run(unknown),
        fixture.lifecycle.begin_start(unknown, expected_revision=0),
        fixture.lifecycle.request_envelope(unknown),
        fixture.lifecycle.record_process_start(
            unknown, expected_revision=1, process_start=sample_process_start()
        ),
        fixture.lifecycle.record_terminal(
            unknown,
            expected_revision=2,
            target_state=CANCELLED,
            primary=primary,
            additional=(),
            native_exit_value=MISSING,
        ),
        fixture.lifecycle.enrich(
            unknown,
            expected_revision=3,
            native_exit_value=MISSING,
            cleanup_complete=True,
            additional=(),
        ),
        fixture.lifecycle.resolve_external_winner(
            unknown, expected_revision=0, primary=primary
        ),
    )
    assert len(results) == len(_PORT_MEMBERS) - 1  # append_event takes an event
    for result in results:
        assert codes_of(result) == (INVARIANT_VIOLATION,)
        (diagnostic,) = result.diagnostics  # type: ignore[union-attr]
        assert "does not exist" in diagnostic.message
    assert fixture.recorder.calls == []  # nothing was recorded for an unknown record


def test_a_coupled_terminal_carries_the_native_exit_value_it_is_given(
    fixture: _Fixture,
) -> None:
    fixture.running(fixture.inv)
    record = ok(
        fixture.lifecycle.record_terminal(
            fixture.inv,
            expected_revision=2,
            target_state=CANCELLED,
            primary=fixture.mint_stage6(PROCESS_CANCELLED),
            additional=(),
            native_exit_value=1,
        )
    )
    assert record.state is CANCELLED
    assert record.native_exit_value == 1
    assert record.process_exit_category is process_exit_category_for(1)
    assert fixture.stored_run().state is EngineRunState.CANCELLED


def test_the_recorder_failure_stops_the_other_writes_too(fixture: _Fixture) -> None:
    refusing = Stage5InvocationLifecycle(
        unit_of_work=fixture.unit_of_work,
        clock=fixture.clock,
        diagnostics=_RefusingRecorder(),
    )
    fixture.running(fixture.inv)
    result = refusing.record_terminal(
        fixture.inv,
        expected_revision=2,
        target_state=EXITED,
        primary=MISSING,
        additional=(fixture.mint(PROCESS_CLEANUP_FAILED),),
        native_exit_value=0,
    )
    assert codes_of(result) == (INVARIANT_VIOLATION,)
    assert fixture.stored_invocation(fixture.inv).state is RUNNING
    fixture.move_run(EngineRunState.CANCELLED)
    result = refusing.record_terminal(  # the alone path records the same way
        fixture.inv,
        expected_revision=2,
        target_state=CANCELLED,
        primary=fixture.mint_stage6(PROCESS_CANCELLED),
        additional=(),
        native_exit_value=MISSING,
    )
    assert codes_of(result) == (INVARIANT_VIOLATION,)
    assert fixture.stored_invocation(fixture.inv).state is RUNNING
    ok(
        fixture.lifecycle.record_terminal(
            fixture.inv,
            expected_revision=2,
            target_state=CANCELLED,
            primary=fixture.mint_stage6(PROCESS_CANCELLED),
            additional=(),
            native_exit_value=MISSING,
        )
    )
    extra = fixture.mint(PROCESS_CLEANUP_FAILED)
    result = refusing.enrich(
        fixture.inv,
        expected_revision=3,
        native_exit_value=MISSING,
        cleanup_complete=True,
        additional=(extra,),
    )
    assert codes_of(result) == (INVARIANT_VIOLATION,)
    assert fixture.stored_invocation(fixture.inv).revision == 3
    fixture.move_run(EngineRunState.CANCELLED, run_id=fixture.run_kind_run)
    primary = fixture.mint_stage6(PROCESS_CANCELLED, invocation_id=fixture.run_kind_inv)
    result = refusing.resolve_external_winner(
        fixture.run_kind_inv, expected_revision=0, primary=primary
    )
    assert codes_of(result) == (INVARIANT_VIOLATION,)
    assert fixture.stored_invocation(fixture.run_kind_inv).state is PENDING
    fixture.cancel_experiment()
    primary = fixture.mint_stage6(
        PROCESS_CANCELLED, invocation_id=fixture.validate_kind_inv
    )
    result = refusing.resolve_external_winner(
        fixture.validate_kind_inv, expected_revision=0, primary=primary
    )
    assert codes_of(result) == (INVARIANT_VIOLATION,)
    assert fixture.stored_invocation(fixture.validate_kind_inv).state is PENDING
    validate_run = fixture.stored_run(fixture.validate_kind_run)
    assert validate_run.state is EngineRunState.VALIDATING


def test_resolve_external_winner_returns_a_stale_revision_conflict_unchanged(
    fixture: _Fixture,
) -> None:
    fixture.move_run(EngineRunState.CANCELLED)
    primary = fixture.mint_stage6(PROCESS_CANCELLED)
    assert codes_of(
        fixture.lifecycle.resolve_external_winner(
            fixture.inv, expected_revision=7, primary=primary
        )
    ) == (CONCURRENCY_CONFLICT,)
    assert fixture.stored_invocation(fixture.inv).state is PENDING
    recorded_before = list(fixture.recorder.calls)
    refused = fixture.lifecycle.resolve_external_winner(
        fixture.inv, expected_revision=-1, primary=primary
    )
    assert _check_of(refused) == "request_shape"  # the alone request
    fixture.cancel_experiment()
    refused = fixture.lifecycle.resolve_external_winner(
        fixture.validate_kind_inv,
        expected_revision=-1,
        primary=fixture.mint_stage6(
            PROCESS_CANCELLED, invocation_id=fixture.validate_kind_inv
        ),
    )
    assert _check_of(refused) == "request_shape"  # the coupled request
    assert fixture.recorder.calls == recorded_before  # neither refusal recorded
    assert fixture.stored_invocation(fixture.validate_kind_inv).state is PENDING


def test_register_request_material_refuses_a_foreign_object(fixture: _Fixture) -> None:
    with pytest.raises(TypeError, match="RequestMaterial"):
        fixture.lifecycle.register_request_material(
            fixture.inv,
            fixture.token_material,  # type: ignore[arg-type]
        )


class _CommitRefusingUnitOfWork:
    """A ``UnitOfWork`` over the fixture's root whose every ``commit`` is a conflict."""

    def __init__(self, inner: InMemoryUnitOfWork) -> None:
        self._inner = inner

    def begin(self) -> _CommitRefusingUnitOfWork:
        return _CommitRefusingUnitOfWork(self._inner.begin())

    def commit(self) -> Result[None]:
        self._inner.rollback()
        return stage5_failure(
            CONCURRENCY_CONFLICT,
            "the commit lost",
            source_component="task5.commit_refusing_unit_of_work",
            timestamp_utc=_INSTANT,
        )

    def rollback(self) -> None:
        self._inner.rollback()

    @property
    def experiments(self) -> Any:
        return self._inner.experiments

    @property
    def engine_runs(self) -> Any:
        return self._inner.engine_runs

    @property
    def command_invocations(self) -> Any:
        return self._inner.command_invocations

    @property
    def retry_decisions(self) -> Any:
        return self._inner.retry_decisions

    @property
    def availability_observations(self) -> Any:
        return self._inner.availability_observations

    @property
    def diagnostics(self) -> Any:
        return self._inner.diagnostics


def test_append_event_returns_a_lost_commit_and_a_conflicting_duplicate_unchanged(
    fixture: _Fixture,
) -> None:
    fixture.running(fixture.inv)
    event = fixture.heartbeat_event()
    refusing = Stage5InvocationLifecycle(
        unit_of_work=_CommitRefusingUnitOfWork(fixture.unit_of_work),
        clock=fixture.clock,
        diagnostics=fixture.recorder,
    )
    assert codes_of(refusing.append_event(event)) == (CONCURRENCY_CONFLICT,)
    assert fixture.store.committed_run_events() == ()
    ok(fixture.lifecycle.append_event(event))
    conflicting = fixture.heartbeat_event(activity_counter=2)
    assert conflicting.sequence == event.sequence
    assert conflicting.content_hash != event.content_hash
    assert codes_of(fixture.lifecycle.append_event(conflicting)) == (
        CONCURRENCY_CONFLICT,
    )
    assert fixture.store.committed_run_events() == (event,)


# --------------------------------------------------------------------------
# The two doubles
# --------------------------------------------------------------------------


def test_the_recorder_double_keeps_the_first_instance_and_reports_every_call(
    fixture: _Fixture,
) -> None:
    first = fixture.mint(PROCESS_CLEANUP_FAILED)
    fixture.clock.advance(1)
    later = fixture.mint(PROCESS_CLEANUP_FAILED)
    assert first.diagnostic_id == later.diagnostic_id
    assert first != later  # the instant differs, the identity does not
    assert ok(fixture.recorder.record(first)) is None
    assert ok(fixture.recorder.record(later)) is None
    assert fixture.store.diagnostics.live[first.diagnostic_id] == first
    assert fixture.recorder.calls == [first.diagnostic_id, later.diagnostic_id]


def test_the_reconciliation_source_lists_targets_in_order_and_reads_run_facts(
    fixture: _Fixture,
) -> None:
    source = InMemoryReconciliationSource(fixture.store)
    earlier = sample_invocation(
        PENDING,
        kind=CommandKind.DESCRIBE,
        invocation_id=f"inv_{UUID_E}",
        adapter_name="adapter.alpha",
        adapter_version="1.0.0",
        request_hash=request_hash_of(fixture.describe_payload),
        created_at_utc=_INSTANT - timedelta(seconds=1),
    )
    fixture.store.command_invocations.live[earlier.invocation_id] = earlier
    seeded = (
        fixture.inv,
        fixture.run_kind_inv,
        fixture.validate_kind_inv,
        fixture.describe_inv,
    )
    # ordered (created_at_utc, invocation_id)
    assert _target_ids(source) == [earlier.invocation_id, *sorted(seeded)]
    fixture.terminal(fixture.inv, CANCELLED)
    assert fixture.inv in _target_ids(source)  # terminal, cleanup_complete false
    ok(
        fixture.lifecycle.enrich(
            fixture.inv,
            expected_revision=3,
            native_exit_value=MISSING,
            cleanup_complete=True,
            additional=(),
        )
    )
    assert fixture.inv not in _target_ids(source)
    assert all(
        _is_target(record) for record in ok(source.list_reconciliation_targets())
    )
    facts = ok(source.run_facts(fixture.run_kind_run))
    run = fixture.stored_run(fixture.run_kind_run)
    assert facts == RunReconciliationFacts(
        run_id=run.run_id,
        experiment_id=run.experiment_id,
        run_state=run.state,
        run_revision=run.revision,
        attempt_token_hash=run.attempt_token_hash,
        request_hash=run.request_hash,
        experiment_state=ExperimentState.RUNNING,
    )
    assert facts.cancelled is False
    fixture.cancel_experiment()
    assert ok(source.run_facts(fixture.run_kind_run)).cancelled is True
    assert codes_of(source.run_facts(f"run_{UUID_D}")) == (INVARIANT_VIOLATION,)


# --------------------------------------------------------------------------
# The pure request helper, against the harness's construction
# --------------------------------------------------------------------------


def _empty_summary() -> ProtocolEventSummary:
    return ProtocolEventSummary(
        accepted_count=0,
        last_sequence=0,
        artifact_declarations=(),
        warnings=(),
        adapter_diagnostics=(),
        redactions=0,
    )


def _result_over(invocation: CommandInvocationRecord) -> CommandResult:
    return CommandResult(
        invocation=invocation,
        protocol_integrity=ProtocolIntegrityStatus.INTACT,
        accepted_events=(),
        diagnostics=(),
        cancelled=invocation.state is CANCELLED,
        timed_out=invocation.state is TIMED_OUT,
    )


def test_semantic_outcome_request_for_matches_the_harness_construction() -> None:
    exited = sample_invocation(EXITED, kind=CommandKind.RUN)
    run = sample_run(EngineRunState.RUNNING)
    summary = _empty_summary()
    request = semantic_outcome_request_for(
        command_result=_result_over(exited),
        output_parse=MISSING,
        protocol_summary=summary,
        run=run,
        candidate_observations=(),
        negotiated_versions=DEFAULT_NEGOTIATED,
    )
    assert request == SemanticOutcomeRequest(
        schema_version="1.0.0",
        invocation_id=exited.invocation_id,
        expected_invocation_revision=exited.revision,
        run_id=run.run_id,
        expected_run_revision=run.revision,
        protocol_summary=summary,
        candidate_observations=(),
        negotiated_versions=DEFAULT_NEGOTIATED,
    )
    assert not isinstance(request.parsed_output, ValidationResultParse | ManifestParse)
    assert not isinstance(request.protocol_failure, Diagnostic)
    manifest = parse_result_manifest(
        b"{}", max_bytes=PROTOCOL_LIMITS_DEFAULT.max_manifest_bytes, token="p" * 32
    )
    validation = parse_validation_result(
        b"{}", max_bytes=PROTOCOL_LIMITS_DEFAULT.max_event_bytes, token="p" * 32
    )
    with_manifest = semantic_outcome_request_for(
        command_result=_result_over(exited),
        output_parse=manifest,
        protocol_summary=summary,
        run=run,
        candidate_observations=(),
        negotiated_versions=DEFAULT_NEGOTIATED,
    )
    assert with_manifest.parsed_output == manifest
    validate_invocation = sample_invocation(EXITED, kind=CommandKind.VALIDATE)
    with_validation = semantic_outcome_request_for(
        command_result=_result_over(validate_invocation),
        output_parse=validation,
        protocol_summary=summary,
        run=run,
        candidate_observations=(),
        negotiated_versions=DEFAULT_NEGOTIATED,
    )
    assert with_validation.parsed_output == validation
    cancelled = sample_invocation(CANCELLED, kind=CommandKind.RUN)
    with pytest.raises(ValueError, match="EXITED"):
        semantic_outcome_request_for(
            command_result=_result_over(cancelled),
            output_parse=MISSING,
            protocol_summary=summary,
            run=run,
            candidate_observations=(),
            negotiated_versions=DEFAULT_NEGOTIATED,
        )
    describe = sample_invocation(EXITED, kind=CommandKind.DESCRIBE)
    with pytest.raises(ValueError, match="DESCRIBE"):
        semantic_outcome_request_for(
            command_result=_result_over(describe),
            output_parse=MISSING,
            protocol_summary=summary,
            run=run,
            candidate_observations=(),
            negotiated_versions=DEFAULT_NEGOTIATED,
        )
    with pytest.raises(ValueError, match="ManifestParse"):
        semantic_outcome_request_for(
            command_result=_result_over(validate_invocation),
            output_parse=manifest,
            protocol_summary=summary,
            run=run,
            candidate_observations=(),
            negotiated_versions=DEFAULT_NEGOTIATED,
        )
    with pytest.raises(ValueError, match="ValidationResultParse"):
        semantic_outcome_request_for(
            command_result=_result_over(exited),
            output_parse=validation,
            protocol_summary=summary,
            run=run,
            candidate_observations=(),
            negotiated_versions=DEFAULT_NEGOTIATED,
        )
    with pytest.raises(ValueError, match="run"):
        semantic_outcome_request_for(
            command_result=_result_over(exited),
            output_parse=MISSING,
            protocol_summary=summary,
            run=sample_run(EngineRunState.RUNNING, run_id=f"run_{UUID_D}"),
            candidate_observations=(),
            negotiated_versions=DEFAULT_NEGOTIATED,
        )


def test_semantic_outcome_request_for_refuses_a_foreign_parse_object() -> None:
    # review F5: a runtime object of neither parse class is refused, never read as
    # "no output file"
    exited = sample_invocation(EXITED, kind=CommandKind.RUN)
    with pytest.raises(TypeError, match="output_parse"):
        semantic_outcome_request_for(
            command_result=_result_over(exited),
            output_parse=_empty_summary(),  # a parse of neither class
            protocol_summary=_empty_summary(),
            run=sample_run(EngineRunState.RUNNING),
            candidate_observations=(),
            negotiated_versions=DEFAULT_NEGOTIATED,
        )
