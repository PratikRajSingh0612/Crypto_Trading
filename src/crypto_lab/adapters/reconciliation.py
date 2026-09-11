"""Command outcome reconciliation (Stage 6 plan sections 3.11, 5.4, 9.2-9.4;
specification 14.1, 14.6, 14.7, 15.7, 17.1, 19.4, 21.2.1).

The three reconcilers turn one ``EXITED`` invocation, its records and the typed parse
outcomes of Tasks 3-5 into one ``SemanticReconciliation``: a ``ReconciliationVerdict``,
the run target that verdict proposes (plan 9.3), exactly one core ``Diagnostic``
minted at the first failing check, and the sanitized evidence the inputs admit. They
take parse outcomes, never bytes; they read the process fact from the invocation and
its semantic reading from ``semantic_exit_reading`` (plan 9.1, consumed and never
restated); and they are pure over their arguments -- no clock (the instant is the
caller's ``now_utc``), no ambient variable, filesystem, process, repository or network.
Nothing here launches a process, transitions a lifecycle record, persists a row,
finalizes an artifact or builds the core run manifest (a Stage 9 record): a verdict is
a proposal the Stage 6 Task 7 operation applies, and no verdict is a success run state.

Four layers stay distinct. **Process facts** (``native_exit_value``,
``process_exit_category``, the terminal state) come from the invocation. The **parsed
adapter declaration** (descriptor envelope, validation result, manifest) is trust class
W or P and never authoritative by itself. The **core verdict** is the
``SemanticReconciliation``. The **authoritative lifecycle effect** belongs to the
operation of plan 10.

**Precedence** (plan 9.2, one rule). A protocol-integrity diagnostic beats everything:
the supervisor's ``protocol_failure`` (present exactly when ``CommandResult.
protocol_integrity`` is ``VIOLATED``) is returned as the primary before any other
check, whatever the exit and whatever the output. Then, in order, the identity, schema,
leakage, path and declaration checks as listed per command; then the exit-derived
code. A favorable exit or a favorable declaration never overrides an earlier check.

**Describe** (plan 5.4): (1) any stdout byte is ``PROTOCOL.STDOUT_CONTAMINATION``;
(2) a nonzero exit reads its plan 9.1 cell with ``output_present: false`` when no
output exists (an exit-``30`` describe without output is ``ADAPTER.UNAVAILABLE``);
(3) exit ``0`` with no output or with bytes that carry no header is
``PROTOCOL.DESCRIBE_OUTPUT_INVALID``; (4) a header identity differing from the
catalog entry (an absent field counts as differing) is
``PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION`` -- identity before schema, specification
21.2.1; (5) the parser's recorded ``failure_code``; (6) a valid envelope is
negotiated: ``NEGOTIATED`` is ``DESCRIBED``, ``FAILED`` is ``DESCRIBE_UNAVAILABLE``
with ``ADAPTER.UNAVAILABLE``. The descriptor is carried whenever the envelope parsed
strict-valid and negotiation whenever it ran. A describe has no run and proposes no
run target.

**Validate** (plan 9.2): (1) ``protocol_failure``; (2) bytes without a header, or an
absent output on an exit that requires one, are ``PROTOCOL.VALIDATION_RESULT_INVALID``;
(3) header ``invocation_id``, ``run_id``, ``request_id`` (``request_id_for(run.
run_id)``) or ``attempt_token_hash`` absent or differing is
``PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION``, evaluated on the permissive header so a
mis-identified and malformed document reports identity; (4) the recorded
``failure_code``; (5) the plan 9.1 column: an agreeing outcome reads the cell, a
disagreeing outcome is ``PROTOCOL.VALIDATION_RESULT_INVALID``, an absent output on a
non-required exit adds ``output_present: false`` to the exit's code, and on exits
``40``-``70`` and unrecognized the output is recorded and the code is the exit's.

**Run** (plan 9.2): (1) ``protocol_failure``; (2) bytes without a header are
``ARTIFACT.RESULT_MANIFEST_INVALID``; (3) header identity; (4) the recorded
``failure_code`` (``PROTOCOL.UNSUPPORTED_VERSION``, ``ARTIFACT.PATH_BOUNDARY_VIOLATION``
or ``ARTIFACT.RESULT_MANIFEST_INVALID``); (5) manifest identity and provenance against
the run, the experiment and the negotiated versions; (6) the ``FINAL_RESULT`` pointer;
(7) a candidate observation containing the raw token is
``SECURITY.SENSITIVE_MATERIAL_LEAKAGE`` (a token in manifest text was redacted by the
parser and is not leakage); (9) a success manifest's declarations equal the accepted
``ARTIFACT_PRODUCED`` declarations as sets of five-tuples; (10) every manifest
declaration has an observation of the same size and hash, else
``ARTIFACT.VALIDATION_FAILED``; (11) the manifest's warnings are a superset of the
accepted ``WARNING`` events; (12) its approximations equal the slot's; (13) the plan
9.1 column: an agreeing non-``FAILED`` status reads the cell (the late
``NOT_APPLICABLE`` and ``UNAVAILABLE`` cite the first explaining adapter diagnostic by
``adapter_error_code`` and ``adapter_manifest_id`` in ``details``), a ``FAILED``
declaration reads the cell's ``declared_failure_code`` (``ENGINE.RUNTIME_FAILURE`` on
exit ``0``, the truthful declaration), any other status is a contradiction, and an
absent manifest is ``ARTIFACT.RESULT_MANIFEST_INVALID`` on ``0``, ``20`` and ``30`` and
the exit's code with ``manifest_present: false`` otherwise. ``RESULT_FINALIZATION_
ELIGIBLE`` carries the sanitized manifest and no run target; the run stays
``RUNNING`` until Stage 9 finalizes ``RESULT`` artifacts.

Task-local readings, declared rather than inferred silently:

- The sanitized manifest is carried, whatever the primary, exactly when a strict-valid
  manifest exists and checks (3), (5), (6), (9), (11) and (12) all pass as pure
  predicates; check (3) joins the plan's five because a manifest that fails identity
  is not this run's manifest and could not lawfully be its ``EVIDENCE``. A leaking
  candidate (7) or a corrupt file (10) leaves a consistent manifest as evidence.
  ``semantic_status`` is present exactly when the sanitized manifest is.
- The strict-valid validation result is carried as ``sanitized_validation_result``
  exactly when it passes the header identity check (3), whatever the verdict.
- ``protocol_failure`` must name the reconciled invocation; a diagnostic minted for
  another invocation is a broken linkage and raises.
- A ``VALIDATE`` summary carrying an artifact declaration or a ``FINAL_RESULT`` is a
  broken linkage (the parser refuses both for a validate) and raises.
- ``candidate_observations`` must be unique on ``relative_path`` and at most
  ``2 * MAX_CANDIDATE_ARTIFACTS`` (the plan 3.12 request bound applied here too).
- The run must belong to the experiment and the slot compatibility must be the
  experiment's frozen entry for the run's slot, else the linkage is broken.
- Every diagnostic ``details`` value is a pure function of the inputs: exit facts, the
  output's byte length and source hash, the NAMES of mismatched fields, counts, and
  the pattern-constrained adapter code and manifest identity of the late rows. No
  header identity value, path, token or free adapter text ever enters a diagnostic,
  so identities are stable under any hostile output and every message is a literal.
- Only an exit-derived ``ENGINE.RUNTIME_FAILURE`` on an unrecognized exit cites the
  invocation's mandatory ``PROCESS.UNRECOGNIZED_PROCESS_EXIT`` primary causally; a
  contradiction or an earlier check on such an exit carries no causal reference.
- ``protocol_failure`` must carry one of the six codes ``parse_protocol_line`` mints
  (plan 9.4 "minted by parser": the five ``PROTOCOL`` rejections and the path-located
  ``ARTIFACT.PATH_BOUNDARY_VIOLATION``); any other diagnostic is a caller error and
  raises, so a core-minted timeout or cancellation can never be relabelled a
  protocol failure here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Final, Self

from pydantic import Field, model_validator
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.catalog import AdapterCatalogEntry
from crypto_lab.adapters.diagnostics import (
    ADAPTER_UNAVAILABLE,
    ARTIFACT_PATH_BOUNDARY_VIOLATION,
    ARTIFACT_RESULT_MANIFEST_INVALID,
    ARTIFACT_VALIDATION_FAILED,
    COMPAT_LATE_NOT_APPLICABLE,
    COMPAT_NOT_APPLICABLE,
    ENGINE_RUNTIME_FAILURE,
    PROTOCOL_ADAPTER_REPORTED_VIOLATION,
    PROTOCOL_DESCRIBE_OUTPUT_INVALID,
    PROTOCOL_EVENT_TOO_LARGE,
    PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
    PROTOCOL_MALFORMED_JSONL,
    PROTOCOL_STDOUT_CONTAMINATION,
    PROTOCOL_UNSUPPORTED_VERSION,
    PROTOCOL_VALIDATION_RESULT_INVALID,
    SCHEMA_REQUEST_INVALID,
    SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
    stage6_diagnostic,
)
from crypto_lab.adapters.envelopes import NegotiatedVersions
from crypto_lab.adapters.events import ProtocolEventSummary
from crypto_lab.adapters.exit_codes import SemanticExitReading, semantic_exit_reading
from crypto_lab.adapters.limits import (
    MAX_CANDIDATE_ARTIFACTS,
    MAX_DECLARED_SIZE_BYTES,
    RESULT_MANIFEST_RELATIVE_PATH,
)
from crypto_lab.adapters.manifests import (
    AdapterResultManifest,
    AdapterValidationResult,
    ManifestParse,
    SanitizedAdapterResultManifest,
    ValidationResultParse,
    sanitize_result_manifest,
)
from crypto_lab.adapters.negotiation import (
    DescriptorParse,
    NegotiationResult,
    negotiate_protocol,
)
from crypto_lab.adapters.paths import RelativeCandidatePath
from crypto_lab.adapters.vocabulary import (
    NegotiationOutcome,
    ReconciliationVerdict,
    SemanticStatus,
)
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.descriptors import AdapterDescriptor
from crypto_lab.domain.diagnostics import Diagnostic, DiagnosticDetailValue
from crypto_lab.domain.engine_run import SUCCESS_ENGINE_RUN_STATES, EngineRunRecord
from crypto_lab.domain.experiment import ExperimentRecord, SlotCompatibility
from crypto_lab.domain.hashing import request_id_for
from crypto_lab.domain.identifiers import Sha256
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)
from crypto_lab.domain.time import require_utc

#: The component every reconciliation diagnostic names.
SOURCE_COMPONENT: Final = "adapters.reconciliation"
#: Plan 3.12: the observation tuple bound (event-declared plus manifest-declared).
_MAX_CANDIDATE_OBSERVATIONS: Final = 2 * MAX_CANDIDATE_ARTIFACTS
#: Plan 9.4 "minted by parser": the codes a ``protocol_failure`` primary may carry
#: (``parse_protocol_line`` mints exactly these six; the path-located one is an
#: ``ARTIFACT_CORRUPTION`` code, so the category alone cannot be pinned).
_PARSER_REJECTION_CODES: Final[frozenset[str]] = frozenset(
    {
        PROTOCOL_STDOUT_CONTAMINATION,
        PROTOCOL_MALFORMED_JSONL,
        PROTOCOL_EVENT_TOO_LARGE,
        PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
        PROTOCOL_UNSUPPORTED_VERSION,
        ARTIFACT_PATH_BOUNDARY_VIOLATION,
    }
)

_K = CommandKind
_V = ReconciliationVerdict
_R = EngineRunState
_S = SemanticStatus

#: Plan 9.3: the run target each verdict proposes; ``None`` proposes none.
_RUN_TARGET_OF_VERDICT: Final[dict[ReconciliationVerdict, EngineRunState | None]] = {
    _V.DESCRIBED: None,
    _V.DESCRIBE_UNAVAILABLE: None,
    _V.VALIDATED_READY: _R.READY,
    _V.NOT_APPLICABLE: _R.NOT_APPLICABLE,
    _V.UNAVAILABLE: _R.UNAVAILABLE,
    _V.FAILED: _R.FAILED,
    _V.RESULT_FINALIZATION_ELIGIBLE: None,
}
#: The verdicts each command kind may reach (plan 9.3).
_VERDICTS_OF_KIND: Final[dict[CommandKind, frozenset[ReconciliationVerdict]]] = {
    _K.DESCRIBE: frozenset({_V.DESCRIBED, _V.DESCRIBE_UNAVAILABLE}),
    _K.VALIDATE: frozenset(
        {_V.VALIDATED_READY, _V.NOT_APPLICABLE, _V.UNAVAILABLE, _V.FAILED}
    ),
    _K.RUN: frozenset(
        {_V.RESULT_FINALIZATION_ELIGIBLE, _V.NOT_APPLICABLE, _V.UNAVAILABLE, _V.FAILED}
    ),
}
#: The three verdicts that mint no diagnostic.
_CLEAN_VERDICTS: Final[frozenset[ReconciliationVerdict]] = frozenset(
    {_V.DESCRIBED, _V.VALIDATED_READY, _V.RESULT_FINALIZATION_ELIGIBLE}
)
#: Plan 9.2: the run states each reconciler admits -- the pre-state and every state
#: the mapping can produce, so one call serves a first application and a replay.
_VALIDATE_ADMITTED_STATES: Final[frozenset[EngineRunState]] = frozenset(
    {_R.VALIDATING, _R.READY, _R.NOT_APPLICABLE, _R.UNAVAILABLE, _R.FAILED}
)
_RUN_ADMITTED_STATES: Final[frozenset[EngineRunState]] = frozenset(
    {_R.RUNNING, _R.NOT_APPLICABLE, _R.UNAVAILABLE, _R.FAILED}
)
_SUCCESS_STATUSES: Final[frozenset[SemanticStatus]] = frozenset(
    {_S.SUCCEEDED, _S.SUCCEEDED_WITH_WARNINGS}
)
#: The two late rows whose primary cites the manifest's explaining diagnostic.
_LATE_CODES: Final[frozenset[str]] = frozenset(
    {COMPAT_LATE_NOT_APPLICABLE, ADAPTER_UNAVAILABLE}
)
#: Fixed message per parser-recorded failure code (plan 3.11), never adapter text.
_PARSE_FAILURE_MESSAGES: Final[dict[str, str]] = {
    PROTOCOL_UNSUPPORTED_VERSION: (
        "adapter output names a protocol or schema version the core does not support"
    ),
    PROTOCOL_DESCRIBE_OUTPUT_INVALID: (
        "describe output is not a valid bootstrap descriptor envelope"
    ),
    PROTOCOL_VALIDATION_RESULT_INVALID: (
        "validation output is not a valid adapter validation result"
    ),
    ARTIFACT_RESULT_MANIFEST_INVALID: (
        "result manifest is not a valid adapter result manifest"
    ),
    ARTIFACT_PATH_BOUNDARY_VIOLATION: (
        "result manifest declares a candidate path outside the relative candidate "
        "grammar"
    ),
}
#: Fixed message per exit-derived code, keyed on the imported constants (plan 9.4:
#: imported rather than respelled), so a drift fails loudly instead of moving an
#: identity through a default message.
_EXIT_MESSAGES: Final[dict[str, str]] = {
    SCHEMA_REQUEST_INVALID: "adapter reported a request or schema validation failure",
    ENGINE_RUNTIME_FAILURE: "adapter or engine reported a runtime failure",
    ADAPTER_UNAVAILABLE: "adapter or engine reported itself unavailable",
    COMPAT_NOT_APPLICABLE: "adapter validation found the strategy not applicable",
    COMPAT_LATE_NOT_APPLICABLE: (
        "adapter run found the strategy not applicable after preflight"
    ),
    PROTOCOL_ADAPTER_REPORTED_VIOLATION: "adapter reported a protocol violation",
}


def _is_missing(value: object) -> bool:
    return value is MISSING


class ReconciliationRuleViolation(ValueError):
    """A caller error the plan 10 operation maps to ``CORE.INVARIANT_VIOLATION``:
    a wrong command kind, a non-``EXITED`` invocation, an inadmissible run state or a
    broken linkage between the supplied records."""


class CandidateObservation(CanonicalModel):
    """One caller-supplied observation of a declared candidate file (plan 3.11; trust
    class K). The observing I/O is the supervisor's (Stage 9 in production, the
    harness in Stage 6); the reconciler only compares."""

    relative_path: RelativeCandidatePath
    observed_size_bytes: int = Field(ge=0, le=MAX_DECLARED_SIZE_BYTES)
    observed_sha256: Sha256
    contains_attempt_token: bool


class SemanticReconciliation(CanonicalModel):
    """The verdict of one command reconciliation (plan 3.11; trust class P).

    ``run_target_state`` is exactly the plan 9.3 target of the verdict and is never a
    success state; ``diagnostics`` is ``(primary_diagnostic,)`` or empty; the three
    clean verdicts carry no diagnostic and every other verdict exactly one; the
    evidence fields belong to their command kind (descriptor and negotiation to
    ``DESCRIBE``, the validation result to ``VALIDATE``, the sanitized manifest and
    its ``semantic_status`` to ``RUN``); a ``DESCRIBED`` verdict requires a
    ``NEGOTIATED`` negotiation and its descriptor; ``RESULT_FINALIZATION_ELIGIBLE``
    requires the sanitized manifest and proposes no run target.
    """

    command_kind: CommandKind
    verdict: ReconciliationVerdict
    run_target_state: EngineRunState | MISSING = MISSING  # type: ignore[valid-type]
    semantic_status: SemanticStatus | MISSING = MISSING  # type: ignore[valid-type]
    primary_diagnostic: Diagnostic | MISSING = MISSING  # type: ignore[valid-type]
    diagnostics: tuple[Diagnostic, ...] = Field(max_length=1)
    sanitized_manifest: SanitizedAdapterResultManifest | MISSING = MISSING  # type: ignore[valid-type]
    sanitized_validation_result: AdapterValidationResult | MISSING = MISSING  # type: ignore[valid-type]
    negotiation: NegotiationResult | MISSING = MISSING  # type: ignore[valid-type]
    descriptor: AdapterDescriptor | MISSING = MISSING  # type: ignore[valid-type]

    @model_validator(mode="after")
    def validate_verdict_shape(self) -> Self:
        kind = self.command_kind
        verdict = self.verdict
        if verdict not in _VERDICTS_OF_KIND[kind]:
            raise ValueError(
                f"verdict {verdict.value} is not a verdict of command_kind {kind.value}"
            )
        expected_target = _RUN_TARGET_OF_VERDICT[verdict]
        if not _is_missing(self.run_target_state) and (
            self.run_target_state in SUCCESS_ENGINE_RUN_STATES
        ):
            raise ValueError("run_target_state is never a success state")
        if (MISSING if expected_target is None else expected_target) != (
            self.run_target_state
        ):
            raise ValueError(
                f"run_target_state must be the plan 9.3 target of verdict "
                f"{verdict.value}"
            )
        primary_present = not _is_missing(self.primary_diagnostic)
        if primary_present and self.diagnostics != (self.primary_diagnostic,):
            raise ValueError("diagnostics must be exactly the primary diagnostic")
        if not primary_present and self.diagnostics:
            raise ValueError("diagnostics without a primary_diagnostic")
        if (verdict in _CLEAN_VERDICTS) is primary_present:
            raise ValueError(
                f"a {verdict.value} verdict "
                + (
                    "carries no diagnostic"
                    if primary_present
                    else "requires a primary_diagnostic"
                )
            )
        self._validate_evidence_fields()
        return self

    def _validate_evidence_fields(self) -> None:
        kind = self.command_kind
        describe = kind is _K.DESCRIBE
        if not describe and not _is_missing(self.descriptor):
            raise ValueError("descriptor is carried by a DESCRIBE reconciliation only")
        if not describe and not _is_missing(self.negotiation):
            raise ValueError("negotiation is carried by a DESCRIBE reconciliation only")
        if kind is not _K.VALIDATE and not _is_missing(
            self.sanitized_validation_result
        ):
            raise ValueError(
                "sanitized_validation_result is carried by a VALIDATE reconciliation "
                "only"
            )
        manifest_present = not _is_missing(self.sanitized_manifest)
        if kind is not _K.RUN and manifest_present:
            raise ValueError(
                "sanitized_manifest is carried by a RUN reconciliation only"
            )
        if _is_missing(self.semantic_status) is manifest_present:
            raise ValueError(
                "semantic_status is present exactly when sanitized_manifest is"
            )
        if manifest_present and self.semantic_status is not (
            self.sanitized_manifest.semantic_status
        ):
            raise ValueError("semantic_status must equal the sanitized manifest's")
        if self.verdict is _V.DESCRIBED:
            if _is_missing(self.descriptor):
                raise ValueError("a DESCRIBED verdict requires its descriptor")
            if _is_missing(self.negotiation):
                raise ValueError("a DESCRIBED verdict requires its negotiation")
            if self.negotiation.outcome is not NegotiationOutcome.NEGOTIATED:
                raise ValueError(
                    "a DESCRIBED verdict requires a NEGOTIATED negotiation"
                )
        elif (
            self.verdict is _V.DESCRIBE_UNAVAILABLE
            and not _is_missing(self.negotiation)
            and self.negotiation.outcome is NegotiationOutcome.NEGOTIATED
        ):
            raise ValueError(
                "a DESCRIBE_UNAVAILABLE verdict cannot carry a NEGOTIATED negotiation"
            )
        if self.verdict is _V.RESULT_FINALIZATION_ELIGIBLE and not manifest_present:
            raise ValueError(
                "a RESULT_FINALIZATION_ELIGIBLE verdict requires the sanitized_manifest"
            )


# --- Shared argument rules ------------------------------------------------------------


def _require_invocation(
    invocation: object, kind: CommandKind, function: str
) -> CommandInvocationRecord:
    if not isinstance(invocation, CommandInvocationRecord):
        raise TypeError("invocation must be a CommandInvocationRecord")
    if invocation.command_kind is not kind:
        raise ReconciliationRuleViolation(
            f"{function} requires a {kind.value} invocation, not "
            f"{invocation.command_kind.value}"
        )
    if invocation.state is not CommandInvocationState.EXITED:
        raise ReconciliationRuleViolation(
            f"{function} requires an EXITED invocation, not {invocation.state.value}"
        )
    return invocation


def _require_run(
    run: object,
    invocation: CommandInvocationRecord,
    admitted: frozenset[EngineRunState],
    function: str,
) -> EngineRunRecord:
    if not isinstance(run, EngineRunRecord):
        raise TypeError("run must be an EngineRunRecord")
    if invocation.run_id != run.run_id:
        raise ReconciliationRuleViolation("the invocation is not linked to the run")
    if run.state not in admitted:
        raise ReconciliationRuleViolation(
            f"{function} does not admit a run in state {run.state.value}"
        )
    return run


def _require_summary(protocol_summary: object) -> ProtocolEventSummary:
    if not isinstance(protocol_summary, ProtocolEventSummary):
        raise TypeError("protocol_summary must be a ProtocolEventSummary")
    return protocol_summary


def _require_protocol_failure(
    protocol_failure: object, invocation: CommandInvocationRecord
) -> Diagnostic | None:
    if _is_missing(protocol_failure):
        return None
    if not isinstance(protocol_failure, Diagnostic):
        raise TypeError("protocol_failure must be a Diagnostic or MISSING")
    if protocol_failure.invocation_id != invocation.invocation_id:
        raise ReconciliationRuleViolation(
            "protocol_failure names another invocation than the one reconciled"
        )
    if protocol_failure.error_code not in _PARSER_REJECTION_CODES:
        raise ReconciliationRuleViolation(
            "protocol_failure must carry a parser rejection code"
        )
    return protocol_failure


def _require_instant(now_utc: object) -> datetime:
    if not isinstance(now_utc, datetime):
        raise TypeError("now_utc must be a datetime")
    return require_utc(now_utc)


# --- Diagnostic minting ---------------------------------------------------------------


def _exit_details(reading: SemanticExitReading) -> dict[str, DiagnosticDetailValue]:
    return {
        "native_exit_value": reading.native_exit_value,
        "process_exit_category": reading.process_exit_category.value,
    }


def _output_details(
    output: DescriptorParse | ValidationResultParse | ManifestParse,
) -> dict[str, DiagnosticDetailValue]:
    return {"byte_length": output.byte_length, "source_hash": output.source_hash}


def _causal(
    invocation: CommandInvocationRecord, reading: SemanticExitReading
) -> tuple[Any, ...]:
    """The unrecognized-exit reference: the invocation's mandatory primary."""
    if reading.recognized:
        return ()
    return (invocation.primary_diagnostic_id,)


def _mint(
    code: str,
    message: str,
    *,
    invocation: CommandInvocationRecord,
    run: EngineRunRecord | None,
    now_utc: datetime,
    details: dict[str, DiagnosticDetailValue],
    causal_diagnostic_ids: tuple[Any, ...] = (),
) -> Diagnostic:
    correlation: dict[str, Any] = {}
    if run is not None:
        correlation["experiment_id"] = run.experiment_id
        correlation["run_id"] = run.run_id
    return stage6_diagnostic(
        code,
        message,
        source_component=SOURCE_COMPONENT,
        timestamp_utc=now_utc,
        invocation_id=invocation.invocation_id,
        details=details,
        causal_diagnostic_ids=causal_diagnostic_ids,
        **correlation,
    )


def _exit_message(code: str) -> str:
    """The literal message of one exit-derived code; a code outside the table is a
    programming error and raises rather than minting a default message."""
    return _EXIT_MESSAGES[code]


def _verdict_payload(
    kind: CommandKind, verdict: ReconciliationVerdict, primary: Diagnostic | None
) -> dict[str, Any]:
    target = _RUN_TARGET_OF_VERDICT[verdict]
    payload: dict[str, Any] = {
        "command_kind": kind,
        "verdict": verdict,
        "diagnostics": () if primary is None else (primary,),
    }
    if target is not None:
        payload["run_target_state"] = target
    if primary is not None:
        payload["primary_diagnostic"] = primary
    return payload


# --- Describe (plan 5.4) --------------------------------------------------------------


def reconcile_describe(
    invocation: CommandInvocationRecord,
    output: DescriptorParse | MISSING,  # type: ignore[valid-type]
    stdout_bytes_seen: int,
    *,
    catalog_entry: AdapterCatalogEntry,
    now_utc: datetime,
) -> SemanticReconciliation:
    """Plan 5.4: reconcile an ``EXITED`` describe against its catalog entry.

    Pure over its arguments; the descriptor and negotiation are carried whenever the
    envelope parsed strict-valid and negotiation ran; no run target is ever proposed.
    """
    invocation = _require_invocation(invocation, _K.DESCRIBE, "reconcile_describe")
    if not (_is_missing(output) or isinstance(output, DescriptorParse)):
        raise TypeError("output must be a DescriptorParse or MISSING")
    if type(stdout_bytes_seen) is not int:
        raise TypeError("stdout_bytes_seen must be a built-in integer")
    if stdout_bytes_seen < 0:
        raise ValueError("stdout_bytes_seen must be non-negative")
    if not isinstance(catalog_entry, AdapterCatalogEntry):
        raise TypeError("catalog_entry must be an AdapterCatalogEntry")
    now_utc = _require_instant(now_utc)
    reading = semantic_exit_reading(_K.DESCRIBE, invocation.native_exit_value)
    parsed = output if isinstance(output, DescriptorParse) else None

    def unavailable(
        code: str,
        message: str,
        details: dict[str, DiagnosticDetailValue],
        *,
        causal_diagnostic_ids: tuple[Any, ...] = (),
        descriptor: object = MISSING,
        negotiation: object = MISSING,
    ) -> SemanticReconciliation:
        primary = _mint(
            code,
            message,
            invocation=invocation,
            run=None,
            now_utc=now_utc,
            details=details,
            causal_diagnostic_ids=causal_diagnostic_ids,
        )
        payload = _verdict_payload(_K.DESCRIBE, _V.DESCRIBE_UNAVAILABLE, primary)
        if not _is_missing(descriptor):
            payload["descriptor"] = descriptor
        if not _is_missing(negotiation):
            payload["negotiation"] = negotiation
        return SemanticReconciliation.model_validate(payload)

    # (1) Describe stdout is never a protocol; any byte is contamination.
    if stdout_bytes_seen > 0:
        return unavailable(
            PROTOCOL_STDOUT_CONTAMINATION,
            "describe wrote to stdout, which carries no protocol for describe",
            {"stdout_bytes_seen": stdout_bytes_seen},
        )
    # (2) A nonzero exit reads its cell; absence is a detail, never a protocol failure.
    if invocation.native_exit_value != 0:
        details = _exit_details(reading)
        if parsed is None:
            details["output_present"] = False
        return unavailable(
            reading.diagnostic_code,
            _exit_message(reading.diagnostic_code),
            details,
            causal_diagnostic_ids=_causal(invocation, reading),
        )
    # (3) Exit 0 owes a descriptor with a readable header.
    if parsed is None:
        return unavailable(
            PROTOCOL_DESCRIBE_OUTPUT_INVALID,
            "describe exited 0 without writing its descriptor output",
            _exit_details(reading),
        )
    if _is_missing(parsed.header):
        return unavailable(
            PROTOCOL_DESCRIBE_OUTPUT_INVALID,
            "describe output is not a JSON object within the descriptor ceiling",
            _output_details(parsed),
        )
    # (4) Identity before schema (specification 21.2.1); absence counts as differing.
    header = parsed.header
    mismatched = [
        name
        for name, expected in (
            ("adapter_name", catalog_entry.adapter_name),
            ("adapter_version", catalog_entry.adapter_version),
            ("executable_hash", catalog_entry.executable_hash),
        )
        if _is_missing(getattr(header, name)) or getattr(header, name) != expected
    ]
    if mismatched:
        return unavailable(
            PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
            "describe output does not identify the catalog entry it was launched for",
            {"mismatched_fields": list(mismatched), **_output_details(parsed)},
        )
    # (5) The parser's recorded classification.
    if not _is_missing(parsed.failure_code):
        return unavailable(
            parsed.failure_code,
            _PARSE_FAILURE_MESSAGES[parsed.failure_code],
            _output_details(parsed),
        )
    # (6) Negotiation over the strict-valid envelope.
    envelope = parsed.envelope
    negotiation = negotiate_protocol(envelope)
    if negotiation.outcome is NegotiationOutcome.NEGOTIATED:
        return SemanticReconciliation.model_validate(
            {
                **_verdict_payload(_K.DESCRIBE, _V.DESCRIBED, None),
                "descriptor": envelope.descriptor,
                "negotiation": negotiation,
            }
        )
    return unavailable(
        ADAPTER_UNAVAILABLE,
        "protocol negotiation found no common version with the adapter",
        {
            "negotiation_outcome": negotiation.outcome.value,
            "reason_codes": list(negotiation.reason_codes),
        },
        descriptor=envelope.descriptor,
        negotiation=negotiation,
    )


# --- Validate (plan 9.2) --------------------------------------------------------------


def _validation_identity_mismatch(
    output: ValidationResultParse,
    invocation: CommandInvocationRecord,
    run: EngineRunRecord,
) -> list[str]:
    """Plan 9.2 check (3) over the permissive header; absence counts as differing."""
    header = output.header
    if _is_missing(header):
        return []
    expected = (
        ("invocation_id", invocation.invocation_id),
        ("run_id", run.run_id),
        ("request_id", request_id_for(run.run_id)),
        ("attempt_token_hash", run.attempt_token_hash),
    )
    return [
        name
        for name, value in expected
        if _is_missing(getattr(header, name)) or getattr(header, name) != value
    ]


def reconcile_validate(
    invocation: CommandInvocationRecord,
    run: EngineRunRecord,
    output: ValidationResultParse | MISSING,  # type: ignore[valid-type]
    protocol_summary: ProtocolEventSummary,
    protocol_failure: Diagnostic | MISSING,  # type: ignore[valid-type]
    *,
    now_utc: datetime,
) -> SemanticReconciliation:
    """Plan 9.2: reconcile an ``EXITED`` validate against its run.

    Admits the run in ``VALIDATING`` or in any state the mapping can produce. Pure
    over its arguments; the strict-valid result of this invocation is carried as
    evidence whatever the verdict.
    """
    invocation = _require_invocation(invocation, _K.VALIDATE, "reconcile_validate")
    run = _require_run(run, invocation, _VALIDATE_ADMITTED_STATES, "reconcile_validate")
    if not (_is_missing(output) or isinstance(output, ValidationResultParse)):
        raise TypeError("output must be a ValidationResultParse or MISSING")
    summary = _require_summary(protocol_summary)
    if summary.artifact_declarations or not _is_missing(summary.final_result):
        raise ReconciliationRuleViolation(
            "a VALIDATE summary carries no artifact declaration or final result"
        )
    failure = _require_protocol_failure(protocol_failure, invocation)
    now_utc = _require_instant(now_utc)
    reading = semantic_exit_reading(_K.VALIDATE, invocation.native_exit_value)

    parsed = output if isinstance(output, ValidationResultParse) else None
    mismatched = (
        _validation_identity_mismatch(parsed, invocation, run)
        if parsed is not None
        else []
    )
    evidence: AdapterValidationResult | None = None
    if (
        parsed is not None
        and not mismatched
        and isinstance(parsed.result, AdapterValidationResult)
    ):
        evidence = parsed.result

    def conclude(
        verdict: ReconciliationVerdict, primary: Diagnostic | None
    ) -> SemanticReconciliation:
        payload = _verdict_payload(_K.VALIDATE, verdict, primary)
        if evidence is not None:
            payload["sanitized_validation_result"] = evidence
        return SemanticReconciliation.model_validate(payload)

    def failed(
        code: str,
        message: str,
        details: dict[str, DiagnosticDetailValue],
        *,
        verdict: ReconciliationVerdict = _V.FAILED,
        causal_diagnostic_ids: tuple[Any, ...] = (),
    ) -> SemanticReconciliation:
        return conclude(
            verdict,
            _mint(
                code,
                message,
                invocation=invocation,
                run=run,
                now_utc=now_utc,
                details=details,
                causal_diagnostic_ids=causal_diagnostic_ids,
            ),
        )

    # (1) A protocol-integrity diagnostic beats everything.
    if failure is not None:
        return conclude(_V.FAILED, failure)
    # (2) Bytes without a header, or absence where the exit owes an output.
    if parsed is not None and _is_missing(parsed.header):
        return failed(
            PROTOCOL_VALIDATION_RESULT_INVALID,
            "validation output is not a JSON object within the result ceiling",
            _output_details(parsed),
        )
    if parsed is None and reading.output_required:
        return failed(
            PROTOCOL_VALIDATION_RESULT_INVALID,
            "validate exited without writing the validation result its exit owes",
            _exit_details(reading),
        )
    if parsed is not None:
        # (3) Identity before the recorded version or schema code (spec 21.2.1).
        if mismatched:
            return failed(
                PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
                "validation result does not identify the active validate invocation",
                {"mismatched_fields": list(mismatched), **_output_details(parsed)},
            )
        # (4) The parser's recorded classification.
        if not _is_missing(parsed.failure_code):
            return failed(
                parsed.failure_code,
                _PARSE_FAILURE_MESSAGES[parsed.failure_code],
                _output_details(parsed),
            )
        # (5) The plan 9.1 column over the strict-valid result.
        result = parsed.result
        agreeing = reading.agreeing_validation_outcome
        if not _is_missing(agreeing) and result.outcome is not agreeing:
            return failed(
                PROTOCOL_VALIDATION_RESULT_INVALID,
                "validation result outcome contradicts the adapter exit",
                {**_exit_details(reading), "declared_outcome": result.outcome.value},
            )
        if _is_missing(reading.diagnostic_code):
            return conclude(_V.VALIDATED_READY, None)
        return failed(
            reading.diagnostic_code,
            _exit_message(reading.diagnostic_code),
            _exit_details(reading),
            verdict=reading.verdict,
            causal_diagnostic_ids=_causal(invocation, reading),
        )
    # (5) Absent output on an exit that does not require one: the exit's code.
    return failed(
        reading.diagnostic_code,
        _exit_message(reading.diagnostic_code),
        {**_exit_details(reading), "output_present": False},
        verdict=reading.verdict,
        causal_diagnostic_ids=_causal(invocation, reading),
    )


# --- Run (plan 9.2) -------------------------------------------------------------------


def _manifest_identity_mismatch(
    output: ManifestParse, invocation: CommandInvocationRecord, run: EngineRunRecord
) -> list[str]:
    """Plan 9.2 check (3) over the permissive header; absence counts as differing."""
    header = output.header
    if _is_missing(header):
        return []
    expected = (
        ("invocation_id", invocation.invocation_id),
        ("run_id", run.run_id),
        ("attempt_token_hash", run.attempt_token_hash),
    )
    return [
        name
        for name, value in expected
        if _is_missing(getattr(header, name)) or getattr(header, name) != value
    ]


def _provenance_mismatch(
    manifest: AdapterResultManifest,
    run: EngineRunRecord,
    experiment: ExperimentRecord,
    negotiated_versions: NegotiatedVersions,
) -> list[str]:
    """Plan 9.2 check (5): every compared value is an input of the call."""
    provenance = manifest.provenance
    spec = experiment.spec
    expected = (
        ("experiment_id", manifest.experiment_id, run.experiment_id),
        ("request_hash", provenance.request_hash, run.request_hash),
        ("experiment_spec_hash", provenance.experiment_spec_hash, experiment.spec_hash),
        ("logical_slot_id", provenance.logical_slot_id, run.logical_slot_id),
        ("attempt_number", provenance.attempt_number, run.attempt_number),
        ("adapter", provenance.adapter, run.adapter),
        ("engine", provenance.engine, run.engine),
        ("comparison_level", provenance.comparison_level, spec.comparison_level),
        (
            "strategy_version_hash",
            provenance.strategy_version_hash,
            spec.strategy_version_hash,
        ),
        (
            "dataset_version_hash",
            provenance.dataset_version_hash,
            spec.dataset_version_hash,
        ),
        ("configuration_hash", provenance.configuration_hash, spec.configuration_hash),
        ("negotiated_versions", provenance.negotiated_versions, negotiated_versions),
    )
    return [name for name, declared, actual in expected if declared != actual]


def _final_result_mismatch(
    manifest: AdapterResultManifest,
    output: ManifestParse,
    summary: ProtocolEventSummary,
) -> list[str]:
    """Plan 9.2 check (6): the ``FINAL_RESULT`` pointer must name this manifest."""
    final = summary.final_result
    if _is_missing(final):
        return ["final_result"]
    expected = (
        (
            "final_result.manifest_relative_path",
            final.manifest_relative_path,
            RESULT_MANIFEST_RELATIVE_PATH,
        ),
        (
            "final_result.source_adapter_result_manifest_hash",
            final.source_adapter_result_manifest_hash,
            output.source_hash,
        ),
        (
            "final_result.semantic_status",
            final.semantic_status,
            manifest.semantic_status,
        ),
    )
    return [name for name, declared, actual in expected if declared != actual]


def _declaration_tuples(
    declarations: tuple[Any, ...],
) -> set[tuple[str, str, str, int, str]]:
    return {
        (
            item.relative_path,
            item.artifact_kind,
            item.media_type,
            item.declared_size_bytes,
            item.declared_sha256,
        )
        for item in declarations
    }


def _declarations_agree(
    manifest: AdapterResultManifest, summary: ProtocolEventSummary
) -> bool:
    """Plan 9.2 check (9), scoped to success statuses: equal sets of five-tuples."""
    if manifest.semantic_status not in _SUCCESS_STATUSES:
        return True
    declared = _declaration_tuples(manifest.candidate_artifacts)
    accepted = _declaration_tuples(
        tuple(record.payload for record in summary.artifact_declarations)
    )
    return declared == accepted


def _warnings_agree(
    manifest: AdapterResultManifest, summary: ProtocolEventSummary
) -> bool:
    """Plan 9.2 check (11): manifest warnings are a superset of the accepted ones,
    compared on canonical bytes after both sides were redacted by their parsers."""
    declared = {canonical_json_bytes(item) for item in manifest.warnings}
    accepted = {canonical_json_bytes(item) for item in summary.warnings}
    return accepted <= declared


def _observation_mismatch(
    manifest: AdapterResultManifest,
    observations: tuple[CandidateObservation, ...],
) -> tuple[int, int]:
    """Plan 9.2 check (10): (declarations without an observation, observations whose
    size or hash differs from the declaration). Event-only paths are not compared."""
    observed = {item.relative_path: item for item in observations}
    unobserved = 0
    differing = 0
    for declaration in manifest.candidate_artifacts:
        observation = observed.get(declaration.relative_path)
        if observation is None:
            unobserved += 1
        elif (
            observation.observed_size_bytes != declaration.declared_size_bytes
            or observation.observed_sha256 != declaration.declared_sha256
        ):
            differing += 1
    return unobserved, differing


def reconcile_run(
    invocation: CommandInvocationRecord,
    run: EngineRunRecord,
    experiment: ExperimentRecord,
    slot_compatibility: SlotCompatibility,
    output: ManifestParse | MISSING,  # type: ignore[valid-type]
    protocol_summary: ProtocolEventSummary,
    candidate_observations: tuple[CandidateObservation, ...],
    negotiated_versions: NegotiatedVersions,
    protocol_failure: Diagnostic | MISSING,  # type: ignore[valid-type]
    *,
    now_utc: datetime,
) -> SemanticReconciliation:
    """Plan 9.2: reconcile an ``EXITED`` run against its run, experiment and slot.

    Admits the run in ``RUNNING`` or in any state the mapping can produce. Pure over
    its arguments. ``RESULT_FINALIZATION_ELIGIBLE`` proposes no run target: only
    Stage 9 commits ``SUCCEEDED`` or ``SUCCEEDED_WITH_WARNINGS`` with the core run
    manifest.
    """
    invocation = _require_invocation(invocation, _K.RUN, "reconcile_run")
    run = _require_run(run, invocation, _RUN_ADMITTED_STATES, "reconcile_run")
    if not isinstance(experiment, ExperimentRecord):
        raise TypeError("experiment must be an ExperimentRecord")
    if not isinstance(slot_compatibility, SlotCompatibility):
        raise TypeError("slot_compatibility must be a SlotCompatibility")
    if run.experiment_id != experiment.experiment_id:
        raise ReconciliationRuleViolation("the run does not belong to the experiment")
    if slot_compatibility.logical_slot_id != run.logical_slot_id:
        raise ReconciliationRuleViolation(
            "the slot compatibility is not the run's slot"
        )
    if _is_missing(experiment.slot_compatibility) or (
        slot_compatibility not in experiment.slot_compatibility
    ):
        raise ReconciliationRuleViolation(
            "the slot compatibility is not the experiment's frozen entry for the slot"
        )
    if not (_is_missing(output) or isinstance(output, ManifestParse)):
        raise TypeError("output must be a ManifestParse or MISSING")
    summary = _require_summary(protocol_summary)
    if type(candidate_observations) is not tuple or not all(
        isinstance(item, CandidateObservation) for item in candidate_observations
    ):
        raise TypeError(
            "candidate_observations must be a tuple of CandidateObservation"
        )
    paths = [item.relative_path for item in candidate_observations]
    if len(set(paths)) != len(paths):
        raise ReconciliationRuleViolation(
            "candidate observations must be unique on relative_path"
        )
    if len(candidate_observations) > _MAX_CANDIDATE_OBSERVATIONS:
        raise ReconciliationRuleViolation(
            f"at most {_MAX_CANDIDATE_OBSERVATIONS} candidate observations are admitted"
        )
    if not isinstance(negotiated_versions, NegotiatedVersions):
        raise TypeError("negotiated_versions must be a NegotiatedVersions")
    failure = _require_protocol_failure(protocol_failure, invocation)
    now_utc = _require_instant(now_utc)
    reading = semantic_exit_reading(_K.RUN, invocation.native_exit_value)

    # The pure predicates, evaluated once; the primary is the first failing check
    # in plan order, the evidence eligibility their conjunction (module docstring).
    parsed = output if isinstance(output, ManifestParse) else None
    manifest = (
        parsed.manifest
        if parsed is not None and isinstance(parsed.manifest, AdapterResultManifest)
        else None
    )
    identity_mismatch = (
        _manifest_identity_mismatch(parsed, invocation, run)
        if parsed is not None
        else []
    )
    provenance_mismatch: list[str] = []
    final_mismatch: list[str] = []
    declarations_ok = True
    warnings_ok = True
    approximations_ok = True
    evidence: SanitizedAdapterResultManifest | None = None
    if parsed is not None and manifest is not None:
        provenance_mismatch = _provenance_mismatch(
            manifest, run, experiment, negotiated_versions
        )
        final_mismatch = _final_result_mismatch(manifest, parsed, summary)
        declarations_ok = _declarations_agree(manifest, summary)
        warnings_ok = _warnings_agree(manifest, summary)
        approximations_ok = (
            manifest.approximations == slot_compatibility.approximation_ids
        )
        if (
            not identity_mismatch
            and not provenance_mismatch
            and not final_mismatch
            and declarations_ok
            and warnings_ok
            and approximations_ok
        ):
            evidence = sanitize_result_manifest(parsed, summary)

    def conclude(
        verdict: ReconciliationVerdict, primary: Diagnostic | None
    ) -> SemanticReconciliation:
        payload = _verdict_payload(_K.RUN, verdict, primary)
        if evidence is not None:
            payload["sanitized_manifest"] = evidence
            payload["semantic_status"] = evidence.semantic_status
        return SemanticReconciliation.model_validate(payload)

    def failed(
        code: str,
        message: str,
        details: dict[str, DiagnosticDetailValue],
        *,
        verdict: ReconciliationVerdict = _V.FAILED,
        causal_diagnostic_ids: tuple[Any, ...] = (),
    ) -> SemanticReconciliation:
        return conclude(
            verdict,
            _mint(
                code,
                message,
                invocation=invocation,
                run=run,
                now_utc=now_utc,
                details=details,
                causal_diagnostic_ids=causal_diagnostic_ids,
            ),
        )

    # (1) A protocol-integrity diagnostic beats everything.
    if failure is not None:
        return conclude(_V.FAILED, failure)
    if parsed is not None:
        # (2) Bytes without a header.
        if _is_missing(parsed.header):
            return failed(
                ARTIFACT_RESULT_MANIFEST_INVALID,
                "result manifest is not a JSON object within the manifest ceiling",
                _output_details(parsed),
            )
        # (3) Identity before the recorded version, path or schema code.
        if identity_mismatch:
            return failed(
                PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
                "result manifest does not identify the active run invocation",
                {
                    "mismatched_fields": list(identity_mismatch),
                    **_output_details(parsed),
                },
            )
        # (4) The parser's recorded classification.
        if not _is_missing(parsed.failure_code):
            return failed(
                parsed.failure_code,
                _PARSE_FAILURE_MESSAGES[parsed.failure_code],
                _output_details(parsed),
            )
        # (5) Provenance against the run, the experiment and the negotiated versions.
        if provenance_mismatch:
            return failed(
                ARTIFACT_RESULT_MANIFEST_INVALID,
                "result manifest provenance differs from the run it claims",
                {
                    "mismatched_fields": list(provenance_mismatch),
                    **_output_details(parsed),
                },
            )
        # (6) The FINAL_RESULT pointer.
        if final_mismatch:
            return failed(
                ARTIFACT_RESULT_MANIFEST_INVALID,
                "the FINAL_RESULT event does not point at the result manifest",
                {"mismatched_fields": list(final_mismatch), **_output_details(parsed)},
            )
    # (7) Leakage: a candidate file containing the raw token.
    leaking = sum(1 for item in candidate_observations if item.contains_attempt_token)
    if leaking:
        return failed(
            SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
            "a candidate artifact contains the raw attempt token",
            {
                "leaking_candidates": leaking,
                "observed_candidates": len(candidate_observations),
            },
        )
    # (8) No parsed manifest: the exit column decides at (13).
    if manifest is not None:
        # (9) Success declarations equal the accepted declarations.
        if not declarations_ok:
            return failed(
                ARTIFACT_RESULT_MANIFEST_INVALID,
                "result manifest declarations differ from the accepted "
                "ARTIFACT_PRODUCED events",
                {
                    "declared_candidates": len(manifest.candidate_artifacts),
                    "accepted_declarations": len(summary.artifact_declarations),
                },
            )
        # (10) Every manifest declaration is observed with the declared size and hash.
        unobserved, differing = _observation_mismatch(manifest, candidate_observations)
        if unobserved or differing:
            return failed(
                ARTIFACT_VALIDATION_FAILED,
                "a declared candidate artifact was not observed with its declared "
                "size and hash",
                {
                    "declared_candidates": len(manifest.candidate_artifacts),
                    "observed_candidates": len(candidate_observations),
                    "unobserved_declarations": unobserved,
                    "mismatched_observations": differing,
                },
            )
        # (11) Manifest warnings are a superset of the accepted WARNING events.
        if not warnings_ok:
            return failed(
                ARTIFACT_RESULT_MANIFEST_INVALID,
                "result manifest warnings omit an accepted WARNING event",
                {
                    "declared_warnings": len(manifest.warnings),
                    "accepted_warnings": len(summary.warnings),
                },
            )
        # (12) Approximations equal the slot's frozen identities.
        if not approximations_ok:
            return failed(
                ARTIFACT_RESULT_MANIFEST_INVALID,
                "result manifest approximations differ from the slot's",
                {"mismatched_fields": ["approximations"]},
            )
        # (13) The plan 9.1 column over the strict-valid manifest.
        status = manifest.semantic_status
        if status in reading.agreeing_semantic_statuses:
            if _is_missing(reading.diagnostic_code):
                return conclude(_V.RESULT_FINALIZATION_ELIGIBLE, None)
            details = _exit_details(reading)
            if reading.diagnostic_code in _LATE_CODES:
                explaining = manifest.diagnostics[0]
                details["adapter_error_code"] = explaining.error_code
                details["adapter_manifest_id"] = manifest.adapter_manifest_id
            return failed(
                reading.diagnostic_code,
                _exit_message(reading.diagnostic_code),
                details,
                verdict=reading.verdict,
                causal_diagnostic_ids=_causal(invocation, reading),
            )
        if status is _S.FAILED and not _is_missing(reading.declared_failure_code):
            return failed(
                reading.declared_failure_code,
                _exit_message(reading.declared_failure_code),
                _exit_details(reading),
                causal_diagnostic_ids=_causal(invocation, reading),
            )
        return failed(
            ARTIFACT_RESULT_MANIFEST_INVALID,
            "result manifest semantic status contradicts the adapter exit",
            {**_exit_details(reading), "declared_semantic_status": status.value},
        )
    # (13) No manifest: required on exits 0, 20 and 30; a detail elsewhere.
    if reading.output_required:
        return failed(
            ARTIFACT_RESULT_MANIFEST_INVALID,
            "run exited without a result manifest its exit owes",
            _exit_details(reading),
        )
    return failed(
        reading.diagnostic_code,
        _exit_message(reading.diagnostic_code),
        {**_exit_details(reading), "manifest_present": False},
        causal_diagnostic_ids=_causal(invocation, reading),
    )
