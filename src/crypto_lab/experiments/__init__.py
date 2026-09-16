"""Experiment orchestration boundary for the research core.

Stage 5 Task 6 (plan sections 10, 3.11, 10.1): the application-owned repository,
reader and unit-of-work ports, the sixteen public operation requests, the Stage 5
diagnostic factory and the experiment, run and invocation lifecycle services;
Task 7 (plan sections 8.2-8.5) adds the causal-closure traversal, the retry
evaluation snapshot assembler, the three-phase ``evaluate_retry`` and the
idempotent ``create_successor`` with its scheduler-eligibility predicate; Task 8
(plan sections 9.2, 9.4 and 9.5) adds ``build_aggregation_input`` and
``aggregate_experiment``, the selected-slot terminal aggregation committed through
the experiment-revision compare-and-swap, with its two verdict-state mappings.
Stage 6 Task 7 (Stage 6 plan sections 3.12 and 10) adds the seventeenth request,
``SemanticOutcomeRequest``, the ``SemanticOutcome`` projection and
``apply_command_semantic_outcome``, the one operation that applies a Task 6
reconciliation to the run and invocation records through the same ports. Stage 7
Task 5 (Stage 7 plan sections 3.6 and 5) adds ``Stage5InvocationLifecycle``, the
application-layer implementation of the supervision lifecycle port over the merged
operations, with its ``DiagnosticRecorder`` port, the transient ``RequestMaterial``
and the pure ``semantic_outcome_request_for``. Concrete port implementations live in
Stage 8's ``persistence`` package; Stages 5 to 7 exercise the ports through
test-resident doubles only.
"""

from crypto_lab.experiments.aggregation import (
    TERMINAL_STATE_OF_VERDICT,
    VERDICT_OF_TERMINAL_STATE,
    aggregate_experiment,
    build_aggregation_input,
)
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    IMMUTABLE_INPUT_MISMATCH,
    INVARIANT_VIOLATION,
    RETRY_DECISION_CONFLICT,
    RETRY_NOT_BEFORE_NOT_REACHED,
    STAGE5_DIAGNOSTIC_CODES,
    UNRECOGNIZED_PROCESS_EXIT,
    DiagnosticPosture,
    stage5_diagnostic,
    stage5_failure,
)
from crypto_lab.experiments.experiment_service import (
    TRANSITION_OWNED_EDGES,
    TRANSITION_OWNED_TARGETS,
    LostSwap,
    cancel_experiment,
    create_experiment,
    queue_experiment,
    replace_experiment_spec,
    run_operation,
    transition_experiment,
)
from crypto_lab.experiments.invocation_service import (
    COUPLED_TERMINAL_TARGETS,
    LINKED_ONLY_INVOCATION_TARGETS,
    LinkedPair,
    begin_linked_launch,
    create_invocation,
    enrich_invocation,
    start_linked_run,
    transition_invocation,
    transition_invocation_and_run,
)
from crypto_lab.experiments.ports import (
    DiagnosticReader,
    EngineRunRepository,
    ExperimentRepository,
    RetryDecisionInsertOutcome,
    RetryDecisionRepository,
    RuntimeAvailabilityObservationReader,
    UnitOfWork,
)
from crypto_lab.experiments.requests import (
    REQUEST_OPERATIONS,
    AttemptCreationRequest,
    CancelExperimentRequest,
    CoupledTransitionRequest,
    ExperimentAggregationRequest,
    ExperimentCreationRequest,
    ExperimentQueueRequest,
    ExperimentSpecReplacementRequest,
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
from crypto_lab.experiments.retry import (
    MAX_CAUSAL_CLOSURE_DEPTH,
    MAX_CAUSAL_CLOSURE_NODES,
    build_retry_evaluation_snapshot,
    create_successor,
    evaluate_retry,
    resolve_causal_closure,
    successor_is_due,
)
from crypto_lab.experiments.run_service import (
    TRANSITION_RUN_OWNED_TARGETS,
    AttemptCreation,
    create_attempt,
    run_replacement,
    run_rule_failure,
    transition_run,
)
from crypto_lab.experiments.semantic_outcome import (
    SemanticOutcome,
    apply_command_semantic_outcome,
)
from crypto_lab.experiments.supervision_lifecycle import (
    SUPERVISION_REASON_CODE,
    DiagnosticRecorder,
    RequestMaterial,
    Stage5InvocationLifecycle,
    semantic_outcome_request_for,
)

__all__ = (
    "CONCURRENCY_CONFLICT",
    "COUPLED_TERMINAL_TARGETS",
    "IMMUTABLE_INPUT_MISMATCH",
    "INVARIANT_VIOLATION",
    "LINKED_ONLY_INVOCATION_TARGETS",
    "MAX_CAUSAL_CLOSURE_DEPTH",
    "MAX_CAUSAL_CLOSURE_NODES",
    "REQUEST_OPERATIONS",
    "RETRY_DECISION_CONFLICT",
    "RETRY_NOT_BEFORE_NOT_REACHED",
    "STAGE5_DIAGNOSTIC_CODES",
    "SUPERVISION_REASON_CODE",
    "TERMINAL_STATE_OF_VERDICT",
    "TRANSITION_OWNED_EDGES",
    "TRANSITION_OWNED_TARGETS",
    "TRANSITION_RUN_OWNED_TARGETS",
    "UNRECOGNIZED_PROCESS_EXIT",
    "VERDICT_OF_TERMINAL_STATE",
    "AttemptCreation",
    "AttemptCreationRequest",
    "CancelExperimentRequest",
    "CoupledTransitionRequest",
    "DiagnosticPosture",
    "DiagnosticReader",
    "DiagnosticRecorder",
    "EngineRunRepository",
    "ExperimentAggregationRequest",
    "ExperimentCreationRequest",
    "ExperimentQueueRequest",
    "ExperimentRepository",
    "ExperimentSpecReplacementRequest",
    "ExperimentTransitionRequest",
    "InvocationCreationRequest",
    "InvocationEnrichmentRequest",
    "InvocationTransitionRequest",
    "LinkedLaunchRequest",
    "LinkedPair",
    "LinkedStartRequest",
    "LostSwap",
    "RequestMaterial",
    "RetryDecisionInsertOutcome",
    "RetryDecisionRepository",
    "RetryEvaluationRequest",
    "RunTransitionRequest",
    "RuntimeAvailabilityObservationReader",
    "SemanticOutcome",
    "SemanticOutcomeRequest",
    "Stage5InvocationLifecycle",
    "SuccessorCreationRequest",
    "UnitOfWork",
    "aggregate_experiment",
    "apply_command_semantic_outcome",
    "begin_linked_launch",
    "build_aggregation_input",
    "build_retry_evaluation_snapshot",
    "cancel_experiment",
    "create_attempt",
    "create_experiment",
    "create_invocation",
    "create_successor",
    "enrich_invocation",
    "evaluate_retry",
    "queue_experiment",
    "replace_experiment_spec",
    "resolve_causal_closure",
    "run_operation",
    "run_replacement",
    "run_rule_failure",
    "semantic_outcome_request_for",
    "stage5_diagnostic",
    "stage5_failure",
    "start_linked_run",
    "successor_is_due",
    "transition_experiment",
    "transition_invocation",
    "transition_invocation_and_run",
    "transition_run",
)
