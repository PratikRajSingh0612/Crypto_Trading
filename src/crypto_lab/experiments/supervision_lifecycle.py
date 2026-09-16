"""The ``experiments`` implementation of the supervision lifecycle port.

Stage 7 plan sections 2.3, 3.6, 4.4 and 5.1-5.4, under specification sections 8.2,
14.8, 15.1, 15.2 and 21.2. The supervisor of ``crypto_lab.process_supervision``
drives the Stage 5 operations through a structural ``InvocationLifecycle`` port;
this module is the application-layer class that satisfies it without importing
that package, so the dependency direction of specification section 8 holds in both
packages and both merged import guards stay unchanged. The Stage 5 operations
remain the sole writers of invocation and run records: every write here is exactly
one merged operation (``transition_invocation``, ``begin_linked_launch``,
``start_linked_run``, ``transition_invocation_and_run``, ``enrich_invocation``) or
one explicit unit of work (``append_event``), every transition request carries the
one opaque, unpersisted reason code ``SUPERVISION_REASON_CODE``, and every
``Diagnostic`` a call references is handed to the injected ``DiagnosticRecorder``
before the swap that references it. Nothing here launches, inspects or terminates
a process, reads a monotonic instant, starts a thread or touches the filesystem.

``RequestMaterial`` is what the lifecycle needs to build one request envelope after
``STARTING``: a token-free describe payload, or the attempt-token material with the
negotiated versions and limits that were used at attempt creation. It is held in
memory per invocation, used by ``begin_start`` (the pre-swap agreement check of plan
4.4) and ``request_envelope`` (a pure function of the ``STARTING`` record and the
material), and dropped at the terminal write; it is never persisted, logged or
hashed beyond the pre-swap comparison of its token hash with the run's durable
``attempt_token_hash``, whose result is never stored or emitted.

Task-local readings, declared here rather than inferred silently (the Task 5
ledger records each):

- The pre-swap revalidation reads the invocation, its run and its experiment in one
  read-only transaction that is rolled back; the swap is the merged operation's own
  ``run_operation`` transaction, which re-checks every precondition. The window
  between the two is the narrow race plan 5.3 assigns to the supervisor's single
  re-issue.
- The provisional ``created_at_utc`` of the pre-swap ``build_engine_run_request``
  check is the injected clock's instant; it enters no record.
- ``record_terminal`` records a supplied primary for every target and lets its
  identity join ``diagnostic_ids``; for ``EXITED`` it becomes the record's
  ``primary_diagnostic_id`` only when the native exit value lies outside the eight
  recognized values (plan 5.1), and a non-``EXITED`` target without a primary is
  refused before any write. The merged operations and the record shape decide
  every other admissibility question.
- The coupled run target is restated through the committed
  ``coupled_run_terminal_state`` from the primary's category, never from a second
  literal table; the alone path is chosen from the reloaded run state alone.
- Every writing member builds and validates its merged request before the recorder
  is touched, so a lifecycle refusal (an unrepresentable request, a missing edge, a
  missing slot observation) records nothing; the recorder then runs before the merged
  operation begins its transaction.
- The material is dropped at the entry of ``record_terminal`` and of
  ``resolve_external_winner``, before the write, whatever the outcome: after either
  call no launch proceeds through this lifecycle.
- ``resolve_external_winner`` records its primary only on the two writing branches.
- ``enrich`` hands the merged operation only the diagnostic identities the reloaded
  record does not yet carry.
- ``semantic_outcome_request_for`` also refuses a run that is not the invocation's
  linked run, one step earlier than the merged operation would.

The lifecycle mints exactly one diagnostic code of its own, ``CORE.INVARIANT_VIOLATION``
for a pre-swap refusal or an unrepresentable request, with a closed ``check`` word in
its details and never a token, payload, dump or message text from the material.
Every other ``Failure`` is a merged operation's or repository's, returned unchanged.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any, Final, Protocol, Self, runtime_checkable

from pydantic import ValidationError, model_validator
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.commands import CommandResult
from crypto_lab.adapters.envelopes import (
    AdapterCommandRequestEnvelope,
    DescribeRequestPayload,
    NegotiatedVersions,
    build_engine_run_request,
    build_request_envelope,
    request_hash_of,
)
from crypto_lab.adapters.events import ProtocolEventSummary, RunEvent
from crypto_lab.adapters.limits import ProtocolLimits
from crypto_lab.adapters.manifests import ManifestParse, ValidationResultParse
from crypto_lab.adapters.reconciliation import CandidateObservation
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.command_invocation import (
    CommandInvocationRecord,
    NativeExitValue,
    ProcessStartFacts,
)
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.engine_run import (
    AttemptTokenMaterial,
    EngineRunRecord,
    coupled_run_terminal_state,
)
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.hashing import attempt_token_hash
from crypto_lab.domain.identifiers import InvocationId
from crypto_lab.domain.lifecycle import (
    RECOGNIZED_NATIVE_EXIT_VALUES,
    TERMINAL_ENGINE_RUN_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.diagnostics import INVARIANT_VIOLATION, stage5_failure
from crypto_lab.experiments.invocation_service import (
    LinkedPair,
    begin_linked_launch,
    enrich_invocation,
    start_linked_run,
    transition_invocation,
    transition_invocation_and_run,
)
from crypto_lab.experiments.ports import UnitOfWork
from crypto_lab.experiments.requests import (
    CoupledTransitionRequest,
    InvocationEnrichmentRequest,
    InvocationTransitionRequest,
    LinkedLaunchRequest,
    LinkedStartRequest,
    RunTransitionRequest,
    SemanticOutcomeRequest,
)

SOURCE_COMPONENT: Final = "experiments.supervision_lifecycle"
#: Plan 5.1: the one opaque, unpersisted label on every transition request.
SUPERVISION_REASON_CODE: Final = "SUPERVISION.TRANSITION"
_K: Final = CommandKind
_C: Final = CommandInvocationState

#: One loaded invocation with its run and experiment (``None`` for a ``DESCRIBE``).
type _Scope = tuple[
    CommandInvocationRecord, EngineRunRecord | None, ExperimentRecord | None
]


def _is_missing(value: object) -> bool:
    return value is MISSING


@runtime_checkable
class DiagnosticRecorder(Protocol):
    """Record one minted diagnostic before the swap that references it.

    Stage 8 persists it; the test-resident double seeds it into the in-memory
    store. Idempotent on ``diagnostic_id``: an identical re-record is accepted and
    the first instance kept.
    """

    def record(self, diagnostic: Diagnostic) -> Result[None]:
        """Make the diagnostic readable through the unit of work's reader."""


class RequestMaterial(CanonicalModel):
    """What the lifecycle needs to build one request envelope after ``STARTING``.

    Trust class K, transient, token-bearing by containment for ``VALIDATE`` and
    ``RUN``: exactly one of a ``describe_payload`` alone, or ``token`` together with
    ``negotiated_versions`` and ``limits``. Never persisted, logged or hashed.
    """

    describe_payload: DescribeRequestPayload | MISSING = MISSING  # type: ignore[valid-type]
    token: AttemptTokenMaterial | MISSING = MISSING  # type: ignore[valid-type]
    negotiated_versions: NegotiatedVersions | MISSING = MISSING  # type: ignore[valid-type]
    limits: ProtocolLimits | MISSING = MISSING  # type: ignore[valid-type]

    @model_validator(mode="after")
    def validate_exactly_one_shape(self) -> Self:
        describe = not _is_missing(self.describe_payload)
        linked = (
            not _is_missing(self.token),
            not _is_missing(self.negotiated_versions),
            not _is_missing(self.limits),
        )
        complete = linked == (True, True, True)
        if (describe and any(linked)) or (not describe and not complete):
            raise ValueError(
                "request material is exactly one of a describe payload alone or "
                "token material with negotiated versions and limits"
            )
        return self


# --------------------------------------------------------------------------
# Reads and refusals
# --------------------------------------------------------------------------


def _load_invocation(
    transaction: UnitOfWork, invocation_id: str
) -> CommandInvocationRecord | Failure:
    loaded = transaction.command_invocations.get(invocation_id)
    if isinstance(loaded, Failure):
        return loaded
    return loaded.value


def _load_run(transaction: UnitOfWork, run_id: str) -> EngineRunRecord | Failure:
    loaded = transaction.engine_runs.get(run_id)
    if isinstance(loaded, Failure):
        return loaded
    return loaded.value


def _load_experiment(
    transaction: UnitOfWork, experiment_id: str
) -> ExperimentRecord | Failure:
    loaded = transaction.experiments.get(experiment_id)
    if isinstance(loaded, Failure):
        return loaded
    return loaded.value


def _invariant(
    message: str,
    *,
    now: datetime,
    check: str,
    invocation: CommandInvocationRecord,
    run: EngineRunRecord | None,
) -> Failure:
    """The lifecycle's one code: a refusal before any write or recording, correlated
    to the invocation and, when the member read the run, to the run and experiment
    (a diagnostic's ``run_id`` requires its ``experiment_id``, so ``enrich``, which
    reads the invocation only, correlates to the invocation alone)."""
    return stage5_failure(
        INVARIANT_VIOLATION,
        message,
        source_component=SOURCE_COMPONENT,
        timestamp_utc=now,
        experiment_id=MISSING if run is None else run.experiment_id,
        run_id=MISSING if run is None else run.run_id,
        invocation_id=invocation.invocation_id,
        details={"check": check},
    )


def _load_scope(
    transaction: UnitOfWork,
    invocation_id: str,
    *,
    now: datetime,
    with_experiment: bool = True,
) -> _Scope | Failure:
    """The invocation and, for a linked kind, its run and (unless the member's plan
    5.1 read set stops at the run) its experiment."""
    record = _load_invocation(transaction, invocation_id)
    if isinstance(record, Failure):
        return record
    if record.command_kind is _K.DESCRIBE:
        return record, None, None
    run_id = record.run_id
    if not isinstance(run_id, str):  # pragma: no cover - the record validator forbids
        # a linked invocation without a run_id; kept so a future shape rule surfaces
        # as a Result.
        return _invariant(
            "a linked invocation carries no run_id",
            now=now,
            check="run_missing",
            invocation=record,
            run=None,
        )
    run = _load_run(transaction, run_id)
    if isinstance(run, Failure):
        return run
    if not with_experiment:
        return record, run, None
    experiment = _load_experiment(transaction, run.experiment_id)
    if isinstance(experiment, Failure):
        return experiment
    return record, run, experiment


def _diagnostic_ids(
    primary: Diagnostic | None, additional: tuple[Diagnostic, ...]
) -> tuple[str, ...]:
    identities = {diagnostic.diagnostic_id for diagnostic in additional}
    if primary is not None:
        identities.add(primary.diagnostic_id)
    return tuple(sorted(identities))


def _slot_observation_id(
    experiment: ExperimentRecord, run: EngineRunRecord
) -> str | None:
    """The frozen observation identity of the run's slot (plan 5.1 ``UNAVAILABLE``)."""
    compatibility = experiment.slot_compatibility
    entries = compatibility if isinstance(compatibility, tuple) else ()
    for entry in entries:
        if entry.logical_slot_id == run.logical_slot_id:
            return entry.availability_observation_id
    return None


def _invocation_of(result: Result[LinkedPair]) -> Result[CommandInvocationRecord]:
    if isinstance(result, Failure):
        return result
    return Success[CommandInvocationRecord](
        outcome="SUCCESS", value=result.value.invocation
    )


def _widened(
    result: Result[CommandInvocationRecord],
) -> Result[CommandInvocationRecord | MISSING]:  # type: ignore[valid-type]
    if isinstance(result, Failure):
        return result
    value: Any = result.value
    return Success(outcome="SUCCESS", value=value)


# --------------------------------------------------------------------------
# The lifecycle
# --------------------------------------------------------------------------


class Stage5InvocationLifecycle:
    """The nine ``InvocationLifecycle`` members over the merged Stage 5 operations.

    Plan 3.6 and 5.1: one merged operation (or one unit of work) per member, the
    reason code ``SUPERVISION_REASON_CODE`` on every transition request, every
    referenced diagnostic recorded before the swap, the coupled run edge for a
    core-won terminal of a linked kind and the alone path beside a run the core
    already terminalized. The class satisfies the port structurally and never
    names it.

    "Before the swap" means before the merged operation begins its transaction: a
    snapshot-isolated reader (the in-memory double today, Stage 8's later) cannot see
    a diagnostic seeded inside it, and two operations read a primary back. The port
    carries diagnostics only as ``primary`` and ``additional``, so a causal referent
    the supervisor passes travels inside ``additional``, is recorded after the
    primary in the order given, and its identity joins the record's
    ``diagnostic_ids``; the lifecycle never reads ``causal_diagnostic_ids``. A
    ``DESCRIBE`` or ``VALIDATE`` handoff replays through ``transition_invocation``,
    which compares no process facts; only the linked ``RUN`` start refuses divergent
    facts.
    """

    def __init__(
        self, *, unit_of_work: UnitOfWork, clock: Clock, diagnostics: DiagnosticRecorder
    ) -> None:
        self._unit_of_work = unit_of_work
        self._clock = clock
        self._diagnostics = diagnostics
        self._materials: dict[str, RequestMaterial] = {}

    def register_request_material(
        self, invocation_id: InvocationId, material: RequestMaterial
    ) -> None:
        """Hold the material one envelope needs; a later registration replaces it."""
        if not isinstance(material, RequestMaterial):
            raise TypeError("material must be a RequestMaterial")
        self._materials[invocation_id] = material

    # -- Reads --------------------------------------------------------------------

    def _read[T](self, read: Callable[[UnitOfWork], T]) -> T:
        """One read-only transaction, always rolled back."""
        transaction = self._unit_of_work.begin()
        try:
            return read(transaction)
        finally:
            transaction.rollback()

    def _scope(
        self, invocation_id: str, *, now: datetime, with_experiment: bool = True
    ) -> _Scope | Failure:
        return self._read(
            lambda transaction: _load_scope(
                transaction, invocation_id, now=now, with_experiment=with_experiment
            )
        )

    def load(self, invocation_id: InvocationId) -> Result[CommandInvocationRecord]:
        return self._read(
            lambda transaction: transaction.command_invocations.get(invocation_id)
        )

    def linked_run(
        self, invocation_id: InvocationId
    ) -> Result[EngineRunRecord | MISSING]:  # type: ignore[valid-type]
        scope = self._scope(
            invocation_id, now=self._clock.now_utc(), with_experiment=False
        )
        if isinstance(scope, Failure):
            return scope
        _, run, _ = scope
        value: Any = MISSING if run is None else run
        return Success(outcome="SUCCESS", value=value)

    # -- Recording ------------------------------------------------------------------

    def _record_all(self, diagnostics: tuple[Diagnostic, ...]) -> Failure | None:
        """Hand every diagnostic to the recorder in the order given, before the swap."""
        for diagnostic in diagnostics:
            recorded = self._diagnostics.record(diagnostic)
            if isinstance(recorded, Failure):
                return recorded
        return None

    # -- The transition requests ----------------------------------------------------

    def _transition_request(
        self,
        invocation: CommandInvocationRecord,
        run: EngineRunRecord | None,
        *,
        now: datetime,
        expected_revision: int,
        target_state: CommandInvocationState,
        process_start: ProcessStartFacts | None = None,
        native_exit_value: object = MISSING,
        primary_diagnostic_id: str | None = None,
        diagnostic_ids: tuple[str, ...] = (),
    ) -> InvocationTransitionRequest | Failure:
        """The ``transition_invocation`` request with the supervision reason code, or
        the ``request_shape`` refusal; built before anything is recorded."""
        payload: dict[str, object] = {
            "schema_version": "1.0.0",
            "invocation_id": invocation.invocation_id,
            "expected_revision": expected_revision,
            "target_state": target_state,
            "reason_code": SUPERVISION_REASON_CODE,
            "diagnostic_ids": diagnostic_ids,
        }
        if process_start is not None:
            payload["process_start"] = process_start
        if not _is_missing(native_exit_value):
            payload["native_exit_value"] = native_exit_value
        if primary_diagnostic_id is not None:
            payload["primary_diagnostic_id"] = primary_diagnostic_id
        try:
            return InvocationTransitionRequest.model_validate(payload)
        except ValidationError:
            return _invariant(
                "the transition request is not representable",
                now=now,
                check="request_shape",
                invocation=invocation,
                run=run,
            )

    def _transition(
        self, request: InvocationTransitionRequest
    ) -> Result[CommandInvocationRecord]:
        """One ``transition_invocation`` call."""
        return transition_invocation(
            request, unit_of_work=self._unit_of_work, clock=self._clock
        )

    def _coupled_request(
        self,
        invocation: CommandInvocationRecord,
        run: EngineRunRecord,
        experiment: ExperimentRecord,
        *,
        now: datetime,
        expected_revision: int,
        target_state: CommandInvocationState,
        primary: Diagnostic,
        diagnostic_ids: tuple[str, ...],
        native_exit_value: object = MISSING,
    ) -> CoupledTransitionRequest | Failure:
        """The ``transition_invocation_and_run`` request, or the refusal: the coupled
        target of plan 5.2 restated from the primary's category, the slot's frozen
        observation for a ``VALIDATE`` moving its run to ``UNAVAILABLE``; built before
        anything is recorded."""
        try:
            mapped = coupled_run_terminal_state(
                invocation.command_kind,
                invocation.state,
                target_state,
                primary_diagnostic_category=primary.category,
            )
        except ValueError:
            return _invariant(
                f"{invocation.state.value} -> {target_state.value} is not a "
                "command-invocation edge",
                now=now,
                check="coupled_target",
                invocation=invocation,
                run=run,
            )
        if not isinstance(mapped, EngineRunState):  # pragma: no cover - the mapping
            # returns MISSING only for DESCRIBE or EXITED, neither of which reaches
            # the coupled path; kept so a widened mapping surfaces as a Result.
            return _invariant(
                f"{target_state.value} couples no run transition",
                now=now,
                check="coupled_target",
                invocation=invocation,
                run=run,
            )
        run_payload: dict[str, object] = {
            "schema_version": "1.0.0",
            "run_id": run.run_id,
            "expected_revision": run.revision,
            "target_state": mapped,
            "reason_code": SUPERVISION_REASON_CODE,
            "primary_terminal_diagnostic_id": primary.diagnostic_id,
        }
        if (
            mapped is EngineRunState.UNAVAILABLE
            and invocation.command_kind is _K.VALIDATE
        ):
            observation = _slot_observation_id(experiment, run)
            if observation is None:
                return _invariant(
                    "the experiment holds no frozen slot compatibility for the run's "
                    "slot",
                    now=now,
                    check="slot_observation_missing",
                    invocation=invocation,
                    run=run,
                )
            run_payload["availability_observation_id"] = observation
        invocation_payload: dict[str, object] = {
            "schema_version": "1.0.0",
            "invocation_id": invocation.invocation_id,
            "expected_revision": expected_revision,
            "target_state": target_state,
            "reason_code": SUPERVISION_REASON_CODE,
            "primary_diagnostic_id": primary.diagnostic_id,
            "diagnostic_ids": diagnostic_ids,
        }
        if not _is_missing(native_exit_value):
            invocation_payload["native_exit_value"] = native_exit_value
        try:
            return CoupledTransitionRequest(
                schema_version="1.0.0",
                invocation=InvocationTransitionRequest.model_validate(
                    invocation_payload
                ),
                run=RunTransitionRequest.model_validate(run_payload),
            )
        except ValidationError:
            return _invariant(
                "the coupled transition request is not representable",
                now=now,
                check="request_shape",
                invocation=invocation,
                run=run,
            )

    def _coupled(
        self, request: CoupledTransitionRequest
    ) -> Result[CommandInvocationRecord]:
        """One ``transition_invocation_and_run`` call."""
        return _invocation_of(
            transition_invocation_and_run(
                request, unit_of_work=self._unit_of_work, clock=self._clock
            )
        )

    # -- The pre-swap revalidation of plan 4.4 -------------------------------------

    def _material_refusal(
        self,
        record: CommandInvocationRecord,
        run: EngineRunRecord | None,
        experiment: ExperimentRecord | None,
        material: RequestMaterial,
        *,
        now: datetime,
    ) -> Failure | None:
        if run is None or experiment is None:
            payload = material.describe_payload
            if not isinstance(payload, DescribeRequestPayload):
                return _invariant(
                    "a DESCRIBE needs a describe payload as its request material",
                    now=now,
                    check="describe_payload_missing",
                    invocation=record,
                    run=None,
                )
            if request_hash_of(payload) != record.request_hash:
                return _invariant(
                    "the describe payload's request hash is not the record's",
                    now=now,
                    check="describe_request_hash",
                    invocation=record,
                    run=None,
                )
            return None
        token = material.token
        negotiated = material.negotiated_versions
        limits = material.limits
        if (
            not isinstance(token, AttemptTokenMaterial)
            or not isinstance(negotiated, NegotiatedVersions)
            or not isinstance(limits, ProtocolLimits)
        ):
            return _invariant(
                "a linked invocation needs token material with negotiated versions "
                "and limits",
                now=now,
                check="token_material_missing",
                invocation=record,
                run=run,
            )
        if token.run_id != run.run_id:
            return _invariant(
                "the token material belongs to another run",
                now=now,
                check="token_run",
                invocation=record,
                run=run,
            )
        if attempt_token_hash(token.attempt_token) != run.attempt_token_hash:
            return _invariant(
                "the token material's hash is not the run's attempt_token_hash",
                now=now,
                check="token_hash",
                invocation=record,
                run=run,
            )
        try:
            provisional = build_engine_run_request(
                run=run,
                experiment=experiment,
                token=token,
                negotiated=negotiated,
                limits=limits,
                created_at_utc=now,
            )
        except (TypeError, ValueError):
            return _invariant(
                "the request material does not rebuild the run's request",
                now=now,
                check="request_material",
                invocation=record,
                run=run,
            )
        if provisional.request_hash != record.request_hash:
            return _invariant(
                "the request hash of the material is not the record's",
                now=now,
                check="request_hash",
                invocation=record,
                run=run,
            )
        if experiment.state is ExperimentState.CANCELLED:
            return _invariant(
                "the experiment is CANCELLED, so the launch cannot proceed",
                now=now,
                check="experiment_cancelled",
                invocation=record,
                run=run,
            )
        return None

    # -- The nine port members --------------------------------------------------------

    def begin_start(
        self, invocation_id: InvocationId, *, expected_revision: int
    ) -> Result[CommandInvocationRecord]:
        now = self._clock.now_utc()
        scope = self._scope(invocation_id, now=now)
        if isinstance(scope, Failure):
            return scope
        record, run, experiment = scope
        material = self._materials.get(invocation_id)
        if material is None:
            return _invariant(
                "no request material is registered for the invocation",
                now=now,
                check="material_missing",
                invocation=record,
                run=run,
            )
        refusal = self._material_refusal(record, run, experiment, material, now=now)
        if refusal is not None:
            return refusal
        if run is None or record.command_kind is _K.VALIDATE:
            if run is not None and run.state is not EngineRunState.VALIDATING:
                return _invariant(
                    "a VALIDATE launches beside a VALIDATING run, not "
                    f"{run.state.value}",
                    now=now,
                    check="run_not_validating",
                    invocation=record,
                    run=run,
                )
            request = self._transition_request(
                record,
                run,
                now=now,
                expected_revision=expected_revision,
                target_state=_C.STARTING,
            )
            if isinstance(request, Failure):
                return request
            return self._transition(request)
        try:
            launch = LinkedLaunchRequest(
                schema_version="1.0.0",
                invocation_id=record.invocation_id,
                expected_invocation_revision=expected_revision,
                run_id=run.run_id,
                expected_run_revision=run.revision,
            )
        except ValidationError:
            return _invariant(
                "the linked launch request is not representable",
                now=now,
                check="request_shape",
                invocation=record,
                run=run,
            )
        return _invocation_of(
            begin_linked_launch(
                launch, unit_of_work=self._unit_of_work, clock=self._clock
            )
        )

    def request_envelope(
        self, invocation_id: InvocationId
    ) -> Result[AdapterCommandRequestEnvelope]:
        now = self._clock.now_utc()
        scope = self._scope(invocation_id, now=now)
        if isinstance(scope, Failure):
            return scope
        record, run, experiment = scope
        material = self._materials.get(invocation_id)
        if material is None:
            return _invariant(
                "no request material is registered for the invocation",
                now=now,
                check="material_missing",
                invocation=record,
                run=run,
            )
        launch_instant = record.launch_attempted_at_utc
        starting = record.state is _C.STARTING
        if not starting or not isinstance(launch_instant, datetime):
            return _invariant(
                f"the request envelope is built for a STARTING record, not "
                f"{record.state.value}",
                now=now,
                check="record_not_starting",
                invocation=record,
                run=run,
            )
        try:
            if run is None or experiment is None:
                describe_payload = material.describe_payload
                if not isinstance(describe_payload, DescribeRequestPayload):
                    return _invariant(
                        "a DESCRIBE needs a describe payload as its request material",
                        now=now,
                        check="describe_payload_missing",
                        invocation=record,
                        run=None,
                    )
                envelope = build_request_envelope(
                    invocation=record, payload=describe_payload
                )
            else:
                token = material.token
                negotiated = material.negotiated_versions
                limits = material.limits
                if (
                    not isinstance(token, AttemptTokenMaterial)
                    or not isinstance(negotiated, NegotiatedVersions)
                    or not isinstance(limits, ProtocolLimits)
                ):
                    return _invariant(
                        "a linked invocation needs token material with negotiated "
                        "versions and limits",
                        now=now,
                        check="token_material_missing",
                        invocation=record,
                        run=run,
                    )
                envelope = build_request_envelope(
                    invocation=record,
                    payload=build_engine_run_request(
                        run=run,
                        experiment=experiment,
                        token=token,
                        negotiated=negotiated,
                        limits=limits,
                        created_at_utc=launch_instant,
                    ),
                )
        except (TypeError, ValueError):
            return _invariant(
                "the registered material does not build the invocation's envelope",
                now=now,
                check="envelope",
                invocation=record,
                run=run,
            )
        return Success[AdapterCommandRequestEnvelope](outcome="SUCCESS", value=envelope)

    def record_process_start(
        self,
        invocation_id: InvocationId,
        *,
        expected_revision: int,
        process_start: ProcessStartFacts,
    ) -> Result[CommandInvocationRecord]:
        now = self._clock.now_utc()
        scope = self._scope(invocation_id, now=now, with_experiment=False)
        if isinstance(scope, Failure):
            return scope
        record, run, _ = scope
        if run is None or record.command_kind is _K.VALIDATE:
            request = self._transition_request(
                record,
                run,
                now=now,
                expected_revision=expected_revision,
                target_state=_C.RUNNING,
                process_start=process_start,
            )
            if isinstance(request, Failure):
                return request
            return self._transition(request)
        try:
            start = LinkedStartRequest(
                schema_version="1.0.0",
                invocation_id=record.invocation_id,
                expected_invocation_revision=expected_revision,
                run_id=run.run_id,
                expected_run_revision=run.revision,
                process_start=process_start,
            )
        except ValidationError:
            return _invariant(
                "the linked start request is not representable",
                now=now,
                check="request_shape",
                invocation=record,
                run=run,
            )
        return _invocation_of(
            start_linked_run(start, unit_of_work=self._unit_of_work, clock=self._clock)
        )

    def record_terminal(
        self,
        invocation_id: InvocationId,
        *,
        expected_revision: int,
        target_state: CommandInvocationState,
        primary: Diagnostic | MISSING,  # type: ignore[valid-type]
        additional: tuple[Diagnostic, ...],
        native_exit_value: NativeExitValue | MISSING,  # type: ignore[valid-type]
    ) -> Result[CommandInvocationRecord]:
        if type(target_state) is not CommandInvocationState:
            raise TypeError("target_state must be a CommandInvocationState member")
        self._materials.pop(invocation_id, None)
        now = self._clock.now_utc()
        scope = self._scope(invocation_id, now=now)
        if isinstance(scope, Failure):
            return scope
        record, run, experiment = scope
        present = primary if isinstance(primary, Diagnostic) else None
        identities = _diagnostic_ids(present, additional)
        if target_state is _C.EXITED:
            unrecognized = (
                isinstance(native_exit_value, int)
                and native_exit_value not in RECOGNIZED_NATIVE_EXIT_VALUES
            )
            primary_id = (
                present.diagnostic_id if present is not None and unrecognized else None
            )
            request = self._transition_request(
                record,
                run,
                now=now,
                expected_revision=expected_revision,
                target_state=target_state,
                native_exit_value=native_exit_value,
                primary_diagnostic_id=primary_id,
                diagnostic_ids=identities,
            )
            if isinstance(request, Failure):
                return request
            recorded = self._record_all(
                (*(() if present is None else (present,)), *additional)
            )
            if recorded is not None:
                return recorded
            return self._transition(request)
        if present is None:
            return _invariant(
                f"a {target_state.value} terminal requires a primary diagnostic",
                now=now,
                check="primary_missing",
                invocation=record,
                run=run,
            )
        terminal_run = run is not None and run.state in TERMINAL_ENGINE_RUN_STATES
        if run is None or experiment is None or terminal_run:
            request = self._transition_request(
                record,
                run,
                now=now,
                expected_revision=expected_revision,
                target_state=target_state,
                native_exit_value=native_exit_value,
                primary_diagnostic_id=present.diagnostic_id,
                diagnostic_ids=identities,
            )
            if isinstance(request, Failure):
                return request
            recorded = self._record_all((present, *additional))
            if recorded is not None:
                return recorded
            return self._transition(request)
        coupled = self._coupled_request(
            record,
            run,
            experiment,
            now=now,
            expected_revision=expected_revision,
            target_state=target_state,
            primary=present,
            diagnostic_ids=identities,
            native_exit_value=native_exit_value,
        )
        if isinstance(coupled, Failure):
            return coupled
        recorded = self._record_all((present, *additional))
        if recorded is not None:
            return recorded
        return self._coupled(coupled)

    def enrich(
        self,
        invocation_id: InvocationId,
        *,
        expected_revision: int,
        native_exit_value: NativeExitValue | MISSING,  # type: ignore[valid-type]
        cleanup_complete: bool,
        additional: tuple[Diagnostic, ...],
    ) -> Result[CommandInvocationRecord]:
        now = self._clock.now_utc()
        record = self._read(
            lambda transaction: _load_invocation(transaction, invocation_id)
        )
        if isinstance(record, Failure):
            return record
        stored = set(record.diagnostic_ids)
        payload: dict[str, object] = {
            "schema_version": "1.0.0",
            "invocation_id": record.invocation_id,
            "expected_revision": expected_revision,
            "additional_diagnostic_ids": tuple(
                sorted(
                    {
                        diagnostic.diagnostic_id
                        for diagnostic in additional
                        if diagnostic.diagnostic_id not in stored
                    }
                )
            ),
        }
        if not _is_missing(native_exit_value):
            payload["native_exit_value"] = native_exit_value
        if cleanup_complete:
            payload["cleanup_complete"] = True
        try:
            request = InvocationEnrichmentRequest.model_validate(payload)
        except ValidationError:
            return _invariant(
                "the enrichment request is not representable",
                now=now,
                check="request_shape",
                invocation=record,
                run=None,
            )
        recorded = self._record_all(additional)
        if recorded is not None:
            return recorded
        return enrich_invocation(
            request, unit_of_work=self._unit_of_work, clock=self._clock
        )

    def append_event(self, event: RunEvent) -> Result[RunEvent]:
        transaction = self._unit_of_work.begin()
        try:
            appended = transaction.engine_runs.append_event(event)
            if isinstance(appended, Failure):
                return appended
            committed = transaction.commit()
            if isinstance(committed, Failure):
                return committed
            return appended
        finally:
            transaction.rollback()

    def resolve_external_winner(
        self,
        invocation_id: InvocationId,
        *,
        expected_revision: int,
        primary: Diagnostic,
    ) -> Result[CommandInvocationRecord | MISSING]:  # type: ignore[valid-type]
        self._materials.pop(invocation_id, None)
        now = self._clock.now_utc()
        scope = self._scope(invocation_id, now=now)
        if isinstance(scope, Failure):
            return scope
        record, run, experiment = scope
        absent: Any = MISSING
        if run is None or experiment is None:
            return Success(outcome="SUCCESS", value=absent)
        if run.state in TERMINAL_ENGINE_RUN_STATES:
            request = self._transition_request(
                record,
                run,
                now=now,
                expected_revision=expected_revision,
                target_state=_C.CANCELLED,
                primary_diagnostic_id=primary.diagnostic_id,
                diagnostic_ids=(primary.diagnostic_id,),
            )
            if isinstance(request, Failure):
                return request
            recorded = self._record_all((primary,))
            if recorded is not None:
                return recorded
            return _widened(self._transition(request))
        if experiment.state is ExperimentState.CANCELLED:
            coupled = self._coupled_request(
                record,
                run,
                experiment,
                now=now,
                expected_revision=expected_revision,
                target_state=_C.CANCELLED,
                primary=primary,
                diagnostic_ids=(primary.diagnostic_id,),
            )
            if isinstance(coupled, Failure):
                return coupled
            recorded = self._record_all((primary,))
            if recorded is not None:
                return recorded
            return _widened(self._coupled(coupled))
        return Success(outcome="SUCCESS", value=absent)


# --------------------------------------------------------------------------
# The pure request helper of plan 5.4
# --------------------------------------------------------------------------


def semantic_outcome_request_for(
    *,
    command_result: CommandResult,
    output_parse: ValidationResultParse | ManifestParse | MISSING,  # type: ignore[valid-type]
    protocol_summary: ProtocolEventSummary,
    run: EngineRunRecord,
    candidate_observations: tuple[CandidateObservation, ...],
    negotiated_versions: NegotiatedVersions,
) -> SemanticOutcomeRequest:
    """Build the seventeenth Stage 5 request exactly as the harness does.

    The parse is present only for an ``EXITED`` invocation, ``protocol_failure`` is
    absent (an ``EXITED`` invocation's protocol integrity is never ``VIOLATED``), and
    the two expected revisions are the post-enrichment invocation's and the stored
    run's. Raises ``TypeError`` for an ``output_parse`` of neither parse class (never
    read as "no output file") and ``ValueError`` unless the invocation is ``EXITED``
    and of a linked kind, when the run is not the invocation's, and for a parse whose
    class does not match the kind. Pure over its arguments.
    """
    if not _is_missing(output_parse) and not isinstance(
        output_parse, ValidationResultParse | ManifestParse
    ):
        raise TypeError(
            "output_parse must be a ValidationResultParse, a ManifestParse or MISSING"
        )
    invocation = command_result.invocation
    if invocation.state is not _C.EXITED:
        raise ValueError(
            "a semantic outcome is applied to an EXITED invocation, not "
            f"{invocation.state.value}"
        )
    kind = invocation.command_kind
    if kind is _K.DESCRIBE:
        raise ValueError("a DESCRIBE invocation has no run and no semantic outcome")
    if invocation.run_id != run.run_id:
        raise ValueError("the run is not the invocation's linked run")
    if kind is _K.VALIDATE and isinstance(output_parse, ManifestParse):
        raise ValueError("a ManifestParse is admitted only for a RUN invocation")
    if kind is _K.RUN and isinstance(output_parse, ValidationResultParse):
        raise ValueError(
            "a ValidationResultParse is admitted only for a VALIDATE invocation"
        )
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "invocation_id": invocation.invocation_id,
        "expected_invocation_revision": invocation.revision,
        "run_id": run.run_id,
        "expected_run_revision": run.revision,
        "protocol_summary": protocol_summary,
        "candidate_observations": candidate_observations,
        "negotiated_versions": negotiated_versions,
    }
    if isinstance(output_parse, ValidationResultParse | ManifestParse):
        payload["parsed_output"] = output_parse
    return SemanticOutcomeRequest.model_validate(payload)
