"""Stage 6 Task 9: the callable end-to-end protocol flow (plan Task 9 step 3).

One scenario over the in-memory ports and the Task 8 offline harness
(``contract.harness.OfflineCommandHarness``) with two selected slots whose frozen
``slot_compatibility`` is ``SUPPORTED`` and ``SUPPORTED_WITH_APPROXIMATION``:
create, transition (``DRAFT -> VALIDATED``) and queue the experiment; describe
``fake.conformant`` and build the available observation; create both attempts;
validate slot A to ``READY`` and slot B to ``NOT_APPLICABLE`` through
``fake.unsupported-capability``; launch slot A's run through ``fake.conformant`` to
``RESULT_FINALIZATION_ELIGIBLE`` with the run still ``RUNNING``; rebuild the ledger
from ``list_events`` and prove it equals the live ledger; feed the captured stdout
lines again under the pre-exit ``RUNNING`` invocation snapshot with an advanced
clock and prove every line is ``EventReplayed`` and ``append_event`` stores nothing
new; prove ``assert_token_absent`` over every record; then aggregate and prove
``NOT_YET_TERMINAL``, the exact Stage 6/Stage 9 boundary.

Every child process is the fake adapter launched by the test-resident harness, never
a production supervisor; no ``RunManifest``, no finalized artifact and no success
run state exists anywhere in the flow. Declared readings, so nothing is inferred
silently:

- The negotiated versions the request material is hashed with are DERIVED from the
  live ``DESCRIBE`` (``negotiated_versions_of`` over the reconciled
  ``NegotiationResult``) and proven equal to the constant the harness hands the
  adapter, which discharges the Task 8 carried note that the harness pins the
  constant rather than deriving it.
- The two-slot experiment and the per-slot attempt are two additions to the
  harness in a subclass, not overrides: the harness's own single-slot helpers are
  untouched and every other step is the committed harness method.
- The "pre-exit ``RUNNING`` snapshot" is rebuilt from the stored ``EXITED``
  invocation by removing the exit-only fields, because the store keeps the latest
  row only; the parser accepts a ``RUNNING`` invocation and nothing else.
- "The live ledger" is the harness's accepted-event tuple and its summary; the
  rebuilt ledger never counts redactions, so that one live-only total is excluded
  from the equality.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from contract.harness import (
    DEFAULT_NEGOTIATED,
    FAKE_ADAPTER_VERSION,
    FAKE_ENGINE,
    REASON,
    CommandRun,
    OfflineCommandHarness,
    assert_token_absent,
    assert_token_only_in_wire_material,
    catalog_entry_for,
)
from contract.scenarios import DEFAULT_TIMEOUT_SECONDS
from crypto_lab.adapters.catalog import FrozenAdapterCatalog
from crypto_lab.adapters.diagnostics import COMPAT_NOT_APPLICABLE
from crypto_lab.adapters.envelopes import NegotiatedVersions, request_material_hash
from crypto_lab.adapters.events import (
    EventAcceptanceContext,
    EventReplayed,
    InvocationEventLedger,
    RunEvent,
    parse_protocol_line,
)
from crypto_lab.adapters.limits import PROTOCOL_LIMITS_DEFAULT
from crypto_lab.adapters.manifests import SanitizedAdapterResultManifest
from crypto_lab.adapters.negotiation import NegotiationResult, negotiated_versions_of
from crypto_lab.adapters.reconciliation import SemanticReconciliation
from crypto_lab.adapters.vocabulary import (
    NegotiationOutcome,
    ReconciliationVerdict,
    SemanticStatus,
)
from crypto_lab.domain.aggregation import AggregationVerdict
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.compatibility import CompatibilityOutcome
from crypto_lab.domain.descriptors import RuntimeAvailabilityObservation
from crypto_lab.domain.engine_run import (
    SUCCESS_ENGINE_RUN_STATES,
    AttemptTokenMaterial,
    EngineRunRecord,
)
from crypto_lab.domain.experiment import (
    AdapterIdentity,
    ExperimentRecord,
    SelectedEngineSlot,
    SlotCompatibility,
)
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.aggregation import aggregate_experiment
from crypto_lab.experiments.experiment_service import (
    create_experiment,
    queue_experiment,
    transition_experiment,
)
from crypto_lab.experiments.requests import (
    AttemptCreationRequest,
    ExperimentAggregationRequest,
    ExperimentCreationRequest,
    ExperimentQueueRequest,
    ExperimentTransitionRequest,
)
from crypto_lab.experiments.run_service import create_attempt
from doubles.experiments import (
    AVAIL_B,
    INSTANT,
    MATERIAL_HASH,
    SLOT_A,
    SLOT_B,
    UUID_C,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    SequentialIdentitySource,
    sample_draft,
)

_CONFORMANT: Final = "fake.conformant"
_UNSUPPORTED: Final = "fake.unsupported-capability"
_APPROXIMATION_ID: Final = f"appx_{UUID_C}"
_SEED: Final = "stage6-protocol-flow"
#: The fields an ``EXITED`` invocation carries and its ``RUNNING`` predecessor
#: cannot (the Stage 5 field-shape table).
_EXIT_ONLY_FIELDS: Final = frozenset(
    {
        "completed_at_utc",
        "native_exit_value",
        "process_exit_category",
        "primary_diagnostic_id",
        "cleanup_completed_at_utc",
        "stderr_artifact_id",
    }
)


def _ok[T](result: Result[T]) -> T:
    if isinstance(result, Failure):
        codes = [item.error_code for item in result.diagnostics]
        raise AssertionError(f"operation failed: {codes}")
    assert isinstance(result, Success)
    return result.value


def _reconciliation(command_run: CommandRun) -> SemanticReconciliation:
    reconciliation = command_run.reconciliation
    assert reconciliation is not None
    return reconciliation


class TwoSlotHarness(OfflineCommandHarness):
    """The Task 8 stand-in plus the two additions this flow needs.

    ``two_slot_experiment`` is the harness's ``new_experiment`` over two slots with
    the frozen compatibility the plan prescribes and slot A's observation taken
    from the live ``DESCRIBE``; ``attempt_for`` is its ``new_attempt`` for a named
    slot with the request material hashed over the DERIVED negotiated versions.
    The raw token is held exactly as the harness holds it, so every committed
    harness method (``validating``, ``validate``, ``ready``, ``run``,
    ``token_for``) works on these runs unchanged.
    """

    def two_slot_experiment(
        self, observation: RuntimeAvailabilityObservation
    ) -> ExperimentRecord:
        draft = sample_draft(
            selected_engine_slots=(
                SelectedEngineSlot(
                    logical_slot_id=SLOT_A,
                    slot_ordinal=0,
                    adapter=AdapterIdentity(
                        adapter_name=_CONFORMANT, adapter_version=FAKE_ADAPTER_VERSION
                    ),
                    engine=FAKE_ENGINE,
                ),
                SelectedEngineSlot(
                    logical_slot_id=SLOT_B,
                    slot_ordinal=1,
                    adapter=AdapterIdentity(
                        adapter_name=_UNSUPPORTED, adapter_version=FAKE_ADAPTER_VERSION
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
        assert created.state is ExperimentState.DRAFT
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
        assert validated.state is ExperimentState.VALIDATED
        compatibility = (
            SlotCompatibility(
                logical_slot_id=SLOT_A,
                outcome=CompatibilityOutcome.SUPPORTED,
                availability_observation_id=observation.availability_observation_id,
                approximation_ids=(),
            ),
            SlotCompatibility(
                logical_slot_id=SLOT_B,
                outcome=CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION,
                availability_observation_id=AVAIL_B,
                approximation_ids=(_APPROXIMATION_ID,),
            ),
        )
        return _ok(
            queue_experiment(
                ExperimentQueueRequest(
                    schema_version="1.0.0",
                    experiment_id=validated.experiment_id,
                    expected_revision=validated.revision,
                    config_derived_retry_policy=validated.spec.retry_policy,
                    material_base_configuration_hash=MATERIAL_HASH,
                    slot_compatibility=compatibility,
                ),
                unit_of_work=self._unit_of_work(),
                clock=self.clock,
            )
        )

    def attempt_for(
        self,
        experiment: ExperimentRecord,
        logical_slot_id: str,
        negotiated: NegotiatedVersions,
    ) -> tuple[ExperimentRecord, EngineRunRecord]:
        request_hash = request_material_hash(
            experiment=experiment,
            logical_slot_id=logical_slot_id,
            attempt_number=1,
            negotiated=negotiated,
            limits=self.limits,
        )
        creation = _ok(
            create_attempt(
                AttemptCreationRequest(
                    schema_version="1.0.0",
                    experiment_id=experiment.experiment_id,
                    logical_slot_id=logical_slot_id,
                    expected_experiment_revision=experiment.revision,
                    request_hash=request_hash,
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

    def list_events(self, invocation_id: str) -> tuple[RunEvent, ...]:
        """The declared port extension, through a transaction of the flow's own."""
        transaction = self._unit_of_work().begin()
        try:
            return _ok(transaction.engine_runs.list_events(invocation_id))
        finally:
            transaction.rollback()

    def committed_rows(self) -> tuple[object, ...]:
        """Every committed row of every table plus every seeded diagnostic."""
        return (
            *self.store.committed_experiments(),
            *self.store.committed_engine_runs(),
            *self.store.committed_run_events(),
            *self.store.committed_command_invocations(),
            *self.store.committed_retry_decisions(),
            *self.store.diagnostics.live.values(),
        )


def _running_snapshot(stored: CommandInvocationRecord) -> CommandInvocationRecord:
    """The invocation as the parser saw it before exit: the stored ``EXITED`` row
    with its exit-only fields removed and the state one edge back."""
    assert stored.state is CommandInvocationState.EXITED
    payload = stored.model_dump(exclude=set(_EXIT_ONLY_FIELDS))
    payload.update(
        state=CommandInvocationState.RUNNING,
        diagnostic_ids=(),
        cleanup_complete=False,
        updated_at_utc=stored.process_started_at_utc,
        revision=stored.revision - 1,
    )
    return CommandInvocationRecord.model_validate(payload)


def test_stage6_protocol_flow(tmp_path: Path) -> None:
    clock = FixedClock(INSTANT)
    catalog = FrozenAdapterCatalog(
        (catalog_entry_for(_CONFORMANT), catalog_entry_for(_UNSUPPORTED)),
        clock=clock,
    )
    harness = TwoSlotHarness(
        InMemoryBackingStore(),
        clock,
        SequentialIdentitySource(_SEED),
        catalog,
        tmp_path / "commands",
        PROTOCOL_LIMITS_DEFAULT,
    )

    # 1. Describe fake.conformant: the live negotiation and the available
    #    observation. The negotiated versions are DERIVED from the live result.
    described = harness.describe(
        _CONFORMANT, FAKE_ADAPTER_VERSION, timeout_seconds=DEFAULT_TIMEOUT_SECONDS
    )
    assert described.command_result.invocation.state is CommandInvocationState.EXITED
    describe_reconciliation = _reconciliation(described)
    assert describe_reconciliation.verdict is ReconciliationVerdict.DESCRIBED
    negotiation = describe_reconciliation.negotiation
    assert isinstance(negotiation, NegotiationResult)
    assert negotiation.outcome is NegotiationOutcome.NEGOTIATED
    negotiated = negotiated_versions_of(negotiation)
    # The Task 8 carried note: the harness hands the adapter a pinned constant; the
    # flow proves the live derivation equals it, so the request material below is
    # exactly what the adapter is asked to honour.
    assert negotiated == DEFAULT_NEGOTIATED
    observation = described.observation
    assert isinstance(observation, RuntimeAvailabilityObservation)
    assert observation.adapter_name == _CONFORMANT
    harness.store.seed_availability_observation(observation)

    # 2. The experiment: DRAFT -> VALIDATED -> QUEUED with two frozen slots.
    experiment = harness.two_slot_experiment(observation)
    assert experiment.state is ExperimentState.QUEUED
    assert [slot.outcome for slot in experiment.slot_compatibility] == [
        CompatibilityOutcome.SUPPORTED,
        CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION,
    ]
    assert experiment.slot_compatibility[0].availability_observation_id == (
        observation.availability_observation_id
    )

    # 3. Both attempts; two distinct raw tokens held by the harness alone.
    experiment, run_a = harness.attempt_for(experiment, SLOT_A, negotiated)
    experiment, run_b = harness.attempt_for(experiment, SLOT_B, negotiated)
    assert experiment.state is ExperimentState.RUNNING
    assert (run_a.state, run_b.state) == (
        EngineRunState.PENDING,
        EngineRunState.PENDING,
    )
    token_a = harness.token_for(run_a.run_id)
    token_b = harness.token_for(run_b.run_id)
    assert token_a != token_b

    # 4. Validate slot A through fake.conformant -> READY.
    validated_a = harness.validate(
        harness.validating(run_a), timeout_seconds=DEFAULT_TIMEOUT_SECONDS
    )
    assert _reconciliation(validated_a).verdict is ReconciliationVerdict.VALIDATED_READY
    assert harness.stored_run(run_a.run_id).state is EngineRunState.READY
    assert len(validated_a.command_result.accepted_events) == 2
    assert_token_only_in_wire_material(validated_a, token_a)

    # 5. Validate slot B through fake.unsupported-capability -> NOT_APPLICABLE.
    validated_b = harness.validate(
        harness.validating(run_b), timeout_seconds=DEFAULT_TIMEOUT_SECONDS
    )
    reconciliation_b = _reconciliation(validated_b)
    assert reconciliation_b.verdict is ReconciliationVerdict.NOT_APPLICABLE
    assert harness.primary_code_of(reconciliation_b) == COMPAT_NOT_APPLICABLE
    stored_b = harness.stored_run(run_b.run_id)
    assert stored_b.state is EngineRunState.NOT_APPLICABLE
    assert stored_b.primary_terminal_diagnostic_id in (
        validated_b.command_result.invocation.diagnostic_ids
    )
    assert_token_only_in_wire_material(validated_b, token_b)

    # 6. Run slot A through fake.conformant -> RESULT_FINALIZATION_ELIGIBLE; the
    #    run stays RUNNING, because only Stage 9 commits success.
    executed = harness.run(
        harness.stored_run(run_a.run_id), timeout_seconds=DEFAULT_TIMEOUT_SECONDS
    )
    outcome = executed.outcome
    assert outcome is not None
    run_reconciliation = _reconciliation(executed)
    assert (
        run_reconciliation.verdict is ReconciliationVerdict.RESULT_FINALIZATION_ELIGIBLE
    )
    assert run_reconciliation.semantic_status is SemanticStatus.SUCCEEDED
    assert outcome.invocation.state is CommandInvocationState.EXITED
    assert outcome.run.state is EngineRunState.RUNNING
    assert harness.stored_run(run_a.run_id).state is EngineRunState.RUNNING
    sanitized = run_reconciliation.sanitized_manifest
    assert isinstance(sanitized, SanitizedAdapterResultManifest)
    assert sanitized.semantic_status is SemanticStatus.SUCCEEDED
    assert sanitized.run_id == run_a.run_id
    assert len(executed.command_result.accepted_events) == 5
    assert executed.replayed_count == 0
    assert executed.rejection is None
    assert_token_only_in_wire_material(executed, token_a)
    invocation = outcome.invocation

    # 7. The ledger rebuilt from list_events equals the live ledger (the live-only
    #    redaction total excluded).
    stored_events = harness.list_events(invocation.invocation_id)
    assert len(stored_events) == 5
    rebuilt = InvocationEventLedger.from_events(stored_events)
    assert rebuilt.events == executed.command_result.accepted_events
    live_summary = executed.protocol_summary
    assert live_summary is not None
    assert rebuilt.summary().model_dump(exclude={"redactions"}) == (
        live_summary.model_dump(exclude={"redactions"})
    )
    assert rebuilt.redactions == 0
    assert rebuilt.final_result_accepted

    # 8. Replay: the captured stdout lines again, under the pre-exit RUNNING
    #    snapshot with an advanced clock; every line is a replay and the store
    #    does not grow.
    events_before = harness.store.committed_run_events()
    snapshot = _running_snapshot(harness.stored_invocation(invocation.invocation_id))
    assert snapshot.invocation_id == invocation.invocation_id
    clock.advance(3600)
    ledger = rebuilt
    current_run = harness.stored_run(run_a.run_id)
    assert len(executed.raw_stdout_lines) == 5
    replays = 0
    for line in executed.raw_stdout_lines:
        replay = parse_protocol_line(
            line,
            acceptance=EventAcceptanceContext(
                invocation=snapshot,
                attempt_token_hash=current_run.attempt_token_hash,
                max_event_bytes=PROTOCOL_LIMITS_DEFAULT.max_event_bytes,
                ledger=ledger,
                clock=clock,
            ),
        )
        assert isinstance(replay, EventReplayed), replay
        ledger = ledger.accept(replay)
        replays += 1
    assert replays == 5
    assert ledger.events == rebuilt.events
    transaction = InMemoryUnitOfWork(harness.store, clock=clock).begin()
    for event in stored_events:
        assert _ok(transaction.engine_runs.append_event(event)) == event
    _ok(transaction.commit())
    assert harness.store.committed_run_events() == events_before

    # 9. No raw token in any committed record or core projection.
    projections: tuple[object, ...] = (
        *harness.committed_rows(),
        outcome,
        describe_reconciliation,
        reconciliation_b,
        run_reconciliation,
        sanitized,
        observation,
        negotiation,
        rebuilt.summary(),
    )
    for token in (token_a, token_b):
        assert_token_absent(projections, token)

    # 10. Aggregate: NOT_YET_TERMINAL, because slot A awaits Stage 9 -- the exact
    #     Stage 6 / Stage 9 boundary. Nothing is written.
    current = harness.stored_experiment(experiment.experiment_id)
    assert current.state is ExperimentState.RUNNING
    rows_before = harness.committed_rows()
    aggregation = _ok(
        aggregate_experiment(
            ExperimentAggregationRequest(
                schema_version="1.0.0",
                experiment_id=current.experiment_id,
                expected_revision=current.revision,
            ),
            unit_of_work=InMemoryUnitOfWork(harness.store, clock=clock),
            clock=clock,
        )
    )
    assert aggregation.verdict is AggregationVerdict.NOT_YET_TERMINAL
    assert aggregation.reason_codes == ()
    assert harness.stored_experiment(experiment.experiment_id).state is (
        ExperimentState.RUNNING
    )
    assert harness.committed_rows() == rows_before
    assert all(
        run.state not in SUCCESS_ENGINE_RUN_STATES
        for run in harness.store.committed_engine_runs()
    )
