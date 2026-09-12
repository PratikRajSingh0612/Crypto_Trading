"""The sixteen public operation requests of Stage 5 (plan section 3.11) and the
seventeenth, Stage 6 Task 7's ``SemanticOutcomeRequest`` (Stage 6 plan 3.12).

Top-level canonical models carrying ``schema_version``, not published as schemas.
Each carries stable identity and expected revisions only, exactly one per plan
section 10.1 operation. No request carries an authoritative attempt count, a
caller-built authoritative snapshot, a caller-selected outcome, denial material,
``retry_not_before_utc``, a reserved successor number, an approximation flag or an
authoritative terminal fact; every such value is derived by the operation from
repository reads (plan 3.2 sources **A** and **D**). ``process_exit_category`` is
never a request field: it is derived from ``native_exit_value`` (plan 6).

Stage 6 Task 7 adds ``SemanticOutcomeRequest`` (Stage 6 plan 3.12, 10): the two
authoritative identities with their expected revisions plus the supervisor's
already-parsed adapter material -- the typed parse outcome, the ledger's bounded
event summary, the caller-observed candidate files, the negotiated versions and the
parser's rejection diagnostic. It carries no verdict, run target, diagnostic,
finalization eligibility or re-derivable hash; the operation recomputes each through
the pure Task 6 reconcilers. It is the one ``experiments`` request whose
``parsed_output`` may carry the raw attempt token (a trust-class-W manifest), so it
is transient: never persisted, logged, hashed or rendered (Stage 6 plan 13).

Task-local readings, declared here:

- ``reason_code`` on the three transition requests is an ``ErrorCode``: a stable
  namespaced label a caller attaches to the transition it asks for; Stage 5
  persists it nowhere.
- ``InvocationTransitionRequest`` requires ``process_start`` exactly when
  ``target_state`` is ``RUNNING`` (plan 3.11) and, when a ``primary_diagnostic_id``
  is supplied, that it is a member of the request's own ``diagnostic_ids`` (the
  record's field 21/22 rule, plan 3.7).
- ``InvocationEnrichmentRequest.cleanup_complete`` is ``Literal[True]`` or absent:
  a request may complete cleanup, never un-complete it.
- ``InvocationCreationRequest.timeout_seconds`` carries only the kind-independent
  envelope ``1..604800``; the kind-specific bound of plan 3.7 is a plan 6 matrix
  cell and therefore a service ``Result``, not a request shape rule. Linkage
  pairing (``run_id`` with ``expected_run_revision``) is likewise left to the
  domain's ``assert_parent_run_eligibility`` so a half-linked request is named
  as such by the service.
- ``ExperimentQueueRequest.slot_compatibility`` is bounded ``1..8``; its alignment
  with the selected slots (omit, duplicate, misorder) is plan 7 check 6 and is
  reported by ``queue_experiment`` as ``CORE.IMMUTABLE_INPUT_MISMATCH``.
- ``REQUEST_OPERATIONS`` records the one-to-one request-to-operation inventory so
  a test can assert it at sixteen (seventeen after Stage 6 Task 7).
- ``SemanticOutcomeRequest.parsed_output`` admits either parse outcome or absence;
  whether the parse outcome matches the invocation's command kind is an operation
  rule checked against the loaded invocation, because the request carries no kind.
  ``candidate_observations`` is bounded at ``MAX_CANDIDATE_OBSERVATIONS`` (the
  union of event-declared and manifest-declared paths) and unique on
  ``relative_path``; the reconciler restates the same bound.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Final, Literal, Self

from pydantic import Field, field_validator, model_validator
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.envelopes import NegotiatedVersions
from crypto_lab.adapters.events import ProtocolEventSummary
from crypto_lab.adapters.limits import MAX_CANDIDATE_ARTIFACTS
from crypto_lab.adapters.manifests import ManifestParse, ValidationResultParse
from crypto_lab.adapters.reconciliation import CandidateObservation
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.command_invocation import (
    MAX_DIAGNOSTIC_IDS,
    MAX_RUN_TIMEOUT_SECONDS,
    MIN_TIMEOUT_SECONDS,
    NativeExitValue,
    ProcessStartFacts,
)
from crypto_lab.domain.diagnostics import Diagnostic, ErrorCode
from crypto_lab.domain.experiment import (
    MAX_SELECTED_ENGINE_SLOTS,
    ExperimentSpecDraft,
    SlotCompatibility,
)
from crypto_lab.domain.identifiers import (
    ArtifactId,
    AvailabilityObservationId,
    CorrelationId,
    DiagnosticId,
    ExperimentId,
    InvocationId,
    LogicalSlotId,
    NormalizedIdentifier,
    RunId,
    Sha256,
)
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.retry import RetryPolicy
from crypto_lab.domain.versioning import SemanticVersion

type Revision = Annotated[int, Field(strict=True, ge=0)]
type DiagnosticIds = Annotated[
    tuple[DiagnosticId, ...], Field(max_length=MAX_DIAGNOSTIC_IDS)
]

#: Stage 6 plan 3.12: the union of event-declared and manifest-declared candidate
#: paths one semantic-outcome request may carry.
MAX_CANDIDATE_OBSERVATIONS: Final = 2 * MAX_CANDIDATE_ARTIFACTS


def _is_missing(value: object) -> bool:
    return value is MISSING


def _sorted_unique(value: tuple[str, ...]) -> tuple[str, ...]:
    if len(set(value)) != len(value):
        raise ValueError("diagnostic identifiers must be unique")
    if value != tuple(sorted(value)):
        raise ValueError("diagnostic identifiers must be sorted")
    return value


class ExperimentCreationRequest(CanonicalModel):
    """Plan 10.1 ``create_experiment``: a draft and the material base hash."""

    schema_version: Literal["1.0.0"]
    spec_draft: ExperimentSpecDraft
    material_base_configuration_hash: Sha256


class ExperimentSpecReplacementRequest(CanonicalModel):
    """Plan 10.1 ``replace_experiment_spec``."""

    schema_version: Literal["1.0.0"]
    experiment_id: ExperimentId
    expected_revision: Revision
    spec_draft: ExperimentSpecDraft
    material_base_configuration_hash: Sha256


class ExperimentTransitionRequest(CanonicalModel):
    """Plan 10.1 ``transition_experiment``."""

    schema_version: Literal["1.0.0"]
    experiment_id: ExperimentId
    expected_revision: Revision
    target_state: ExperimentState
    reason_code: ErrorCode


class ExperimentQueueRequest(CanonicalModel):
    """Plan 10.1 ``queue_experiment``: the freeze inputs of plan 7."""

    schema_version: Literal["1.0.0"]
    experiment_id: ExperimentId
    expected_revision: Revision
    config_derived_retry_policy: RetryPolicy
    material_base_configuration_hash: Sha256
    slot_compatibility: tuple[SlotCompatibility, ...] = Field(
        min_length=1, max_length=MAX_SELECTED_ENGINE_SLOTS
    )


class CancelExperimentRequest(CanonicalModel):
    """Plan 10.1 ``cancel_experiment``: the durable correlation identity of 9.1."""

    schema_version: Literal["1.0.0"]
    experiment_id: ExperimentId
    expected_revision: Revision
    correlation_id: CorrelationId


class AttemptCreationRequest(CanonicalModel):
    """Plan 10.1 ``create_attempt``: attempt 1 of one selected slot."""

    schema_version: Literal["1.0.0"]
    experiment_id: ExperimentId
    logical_slot_id: LogicalSlotId
    expected_experiment_revision: Revision
    request_hash: Sha256


class RunTransitionRequest(CanonicalModel):
    """Plan 10.1 ``transition_run``: a core-decision edge of plan 5."""

    schema_version: Literal["1.0.0"]
    run_id: RunId
    expected_revision: Revision
    target_state: EngineRunState
    reason_code: ErrorCode
    primary_terminal_diagnostic_id: DiagnosticId | MISSING = MISSING  # type: ignore[valid-type]
    availability_observation_id: AvailabilityObservationId | MISSING = MISSING  # type: ignore[valid-type]


class InvocationCreationRequest(CanonicalModel):
    """Plan 10.1 ``create_invocation``: one command against an optional run."""

    schema_version: Literal["1.0.0"]
    command_kind: CommandKind
    adapter_name: NormalizedIdentifier
    adapter_version: SemanticVersion
    run_id: RunId | MISSING = MISSING  # type: ignore[valid-type]
    expected_run_revision: Revision | MISSING = MISSING  # type: ignore[valid-type]
    request_hash: Sha256
    timeout_seconds: int = Field(
        strict=True, ge=MIN_TIMEOUT_SECONDS, le=MAX_RUN_TIMEOUT_SECONDS
    )


class LinkedLaunchRequest(CanonicalModel):
    """Plan 10.1 ``begin_linked_launch``: launch the invocation and start the run."""

    schema_version: Literal["1.0.0"]
    invocation_id: InvocationId
    expected_invocation_revision: Revision
    run_id: RunId
    expected_run_revision: Revision


class InvocationTransitionRequest(CanonicalModel):
    """Plan 10.1 ``transition_invocation``: one plan 6 edge of a single invocation."""

    schema_version: Literal["1.0.0"]
    invocation_id: InvocationId
    expected_revision: Revision
    target_state: CommandInvocationState
    reason_code: ErrorCode
    process_start: ProcessStartFacts | MISSING = MISSING  # type: ignore[valid-type]
    native_exit_value: NativeExitValue | MISSING = MISSING  # type: ignore[valid-type]
    primary_diagnostic_id: DiagnosticId | MISSING = MISSING  # type: ignore[valid-type]
    diagnostic_ids: DiagnosticIds

    @field_validator("diagnostic_ids")
    @classmethod
    def validate_diagnostic_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_unique(value)

    @model_validator(mode="after")
    def validate_process_start_and_primary(self) -> Self:
        present = not _is_missing(self.process_start)
        running = self.target_state is CommandInvocationState.RUNNING
        if running and not present:
            raise ValueError(
                "process_start is required exactly when target_state is RUNNING"
            )
        if present and not running:
            raise ValueError(
                "process_start is prohibited unless target_state is RUNNING"
            )
        if (
            not _is_missing(self.primary_diagnostic_id)
            and self.primary_diagnostic_id not in self.diagnostic_ids
        ):
            raise ValueError("primary_diagnostic_id must be a member of diagnostic_ids")
        return self


class LinkedStartRequest(CanonicalModel):
    """Plan 10.1 ``start_linked_run``: the process-start handoff of a ``RUN``."""

    schema_version: Literal["1.0.0"]
    invocation_id: InvocationId
    expected_invocation_revision: Revision
    run_id: RunId
    expected_run_revision: Revision
    process_start: ProcessStartFacts


class InvocationEnrichmentRequest(CanonicalModel):
    """Plan 10.1 ``enrich_invocation``: the four write-once enrichments of plan 6."""

    schema_version: Literal["1.0.0"]
    invocation_id: InvocationId
    expected_revision: Revision
    native_exit_value: NativeExitValue | MISSING = MISSING  # type: ignore[valid-type]
    cleanup_complete: Literal[True] | MISSING = MISSING  # type: ignore[valid-type]
    stderr_artifact_id: ArtifactId | MISSING = MISSING  # type: ignore[valid-type]
    additional_diagnostic_ids: DiagnosticIds

    @field_validator("additional_diagnostic_ids")
    @classmethod
    def validate_additional_diagnostic_ids(
        cls, value: tuple[str, ...]
    ) -> tuple[str, ...]:
        return _sorted_unique(value)


class CoupledTransitionRequest(CanonicalModel):
    """Plan 10.1 ``transition_invocation_and_run``: a terminal outcome and its coupled
    run transition, committed together or not at all."""

    schema_version: Literal["1.0.0"]
    invocation: InvocationTransitionRequest
    run: RunTransitionRequest


class RetryEvaluationRequest(CanonicalModel):
    """Plan 10.1 ``evaluate_retry`` (Task 7)."""

    schema_version: Literal["1.0.0"]
    experiment_id: ExperimentId
    logical_slot_id: LogicalSlotId
    predecessor_run_id: RunId
    expected_experiment_revision: Revision
    expected_predecessor_revision: Revision


class SuccessorCreationRequest(CanonicalModel):
    """Plan 10.1 ``create_successor`` (Task 7)."""

    schema_version: Literal["1.0.0"]
    experiment_id: ExperimentId
    logical_slot_id: LogicalSlotId
    predecessor_run_id: RunId
    expected_experiment_revision: Revision
    request_hash: Sha256


class ExperimentAggregationRequest(CanonicalModel):
    """Plan 10.1 ``aggregate_experiment`` (Task 8)."""

    schema_version: Literal["1.0.0"]
    experiment_id: ExperimentId
    expected_revision: Revision


class SemanticOutcomeRequest(CanonicalModel):
    """Stage 6 plan 3.12 ``apply_command_semantic_outcome`` (Stage 6 Task 7).

    The seventeenth request: the ``EXITED`` invocation and its run with their
    expected revisions, the typed parse outcome of the command's output file
    (``MISSING`` when no output file existed; a ``ManifestParse`` only for a ``RUN``,
    a ``ValidationResultParse`` only for a ``VALIDATE`` -- checked by the operation
    against the loaded invocation), the ledger's ``ProtocolEventSummary``, the
    caller-observed candidate files (the union of event-declared and
    manifest-declared paths, unique on ``relative_path``), the token-free versions
    the supervisor handed the adapter, and the parser's rejection diagnostic,
    present exactly when ``CommandResult.protocol_integrity`` is ``VIOLATED``. No
    verdict, run target, diagnostic, eligibility or hash is caller-selected.
    """

    schema_version: Literal["1.0.0"]
    invocation_id: InvocationId
    expected_invocation_revision: Revision
    run_id: RunId
    expected_run_revision: Revision
    parsed_output: ValidationResultParse | ManifestParse | MISSING = MISSING  # type: ignore[valid-type]
    protocol_summary: ProtocolEventSummary
    candidate_observations: tuple[CandidateObservation, ...] = Field(
        max_length=MAX_CANDIDATE_OBSERVATIONS
    )
    negotiated_versions: NegotiatedVersions
    protocol_failure: Diagnostic | MISSING = MISSING  # type: ignore[valid-type]

    @field_validator("candidate_observations")
    @classmethod
    def validate_candidate_observations(
        cls, value: tuple[CandidateObservation, ...]
    ) -> tuple[CandidateObservation, ...]:
        paths = [item.relative_path for item in value]
        if len(set(paths)) != len(paths):
            raise ValueError("candidate observations must be unique on relative_path")
        return value


#: Plan 3.11: exactly one request per plan 10.1 operation, sixteen each, plus the
#: seventeenth of Stage 6 plan 3.12, appended last.
REQUEST_OPERATIONS: Final[Mapping[type[CanonicalModel], str]] = {
    ExperimentCreationRequest: "create_experiment",
    ExperimentSpecReplacementRequest: "replace_experiment_spec",
    ExperimentTransitionRequest: "transition_experiment",
    ExperimentQueueRequest: "queue_experiment",
    CancelExperimentRequest: "cancel_experiment",
    AttemptCreationRequest: "create_attempt",
    RunTransitionRequest: "transition_run",
    InvocationCreationRequest: "create_invocation",
    LinkedLaunchRequest: "begin_linked_launch",
    InvocationTransitionRequest: "transition_invocation",
    LinkedStartRequest: "start_linked_run",
    InvocationEnrichmentRequest: "enrich_invocation",
    CoupledTransitionRequest: "transition_invocation_and_run",
    RetryEvaluationRequest: "evaluate_retry",
    SuccessorCreationRequest: "create_successor",
    ExperimentAggregationRequest: "aggregate_experiment",
    SemanticOutcomeRequest: "apply_command_semantic_outcome",
}
