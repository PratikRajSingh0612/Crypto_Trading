"""The Stage 6 plan section 11.2 scenario table as data (Stage 6 Task 8).

Every fake-adapter behaviour the harness provokes maps to exactly one row here and
every row is exercised by exactly one of the four contract test modules
(``test_describe_contract``, ``test_validate_contract``, ``test_run_contract``,
``test_protocol_failure_contract``); ``test_harness_safety`` pins that partition.
Row 26 (``fake.process-timeout``) is three entries, one per command, and row 28 is
five entries, one per exit value, so the table holds 58 entries over the plan's 52
rows. The five adapter-side verification vectors of section 11.2 follow the table.

"Expected" names the invocation terminal state, the stored run state (``None`` for
a describe), the reconciliation verdict (``None`` for a core-won terminal, which is
never reconciled), the primary diagnostic code and any secondary code. Every value
is a plan literal; nothing here launches, times or reads anything.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final

from crypto_lab.adapters.diagnostics import (
    ADAPTER_UNAVAILABLE,
    ARTIFACT_PATH_BOUNDARY_VIOLATION,
    ARTIFACT_RESULT_MANIFEST_INVALID,
    ARTIFACT_VALIDATION_FAILED,
    COMPAT_LATE_NOT_APPLICABLE,
    COMPAT_NOT_APPLICABLE,
    ENGINE_RUNTIME_FAILURE,
    PROCESS_CANCELLED,
    PROCESS_DESCRIBE_TIMED_OUT,
    PROCESS_MISSING_HEARTBEAT,
    PROCESS_RUN_TIMED_OUT,
    PROCESS_STDERR_TRUNCATED,
    PROCESS_UNRECOGNIZED_PROCESS_EXIT,
    PROCESS_VALIDATE_TIMED_OUT,
    PROTOCOL_ADAPTER_REPORTED_VIOLATION,
    PROTOCOL_EVENT_TOO_LARGE,
    PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
    PROTOCOL_MALFORMED_JSONL,
    PROTOCOL_STDOUT_CONTAMINATION,
    PROTOCOL_UNSUPPORTED_VERSION,
    SCHEMA_REQUEST_INVALID,
    SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
)
from crypto_lab.adapters.limits import (
    MAX_EVENT_LINE_BYTES,
    MAX_RESULT_MANIFEST_BYTES,
    MAX_STDERR_BYTES,
    MIN_EVENT_LINE_BYTES,
    MIN_RESULT_MANIFEST_BYTES,
    MIN_STDERR_BYTES,
    PROTOCOL_LIMITS_DEFAULT,
    ProtocolLimits,
)
from crypto_lab.adapters.vocabulary import (
    NegotiationOutcome,
    ReconciliationVerdict,
    SemanticStatus,
)
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)

_K = CommandKind
_C = CommandInvocationState
_R = EngineRunState
_V = ReconciliationVerdict
_S = SemanticStatus

#: The plan's default command timeouts for the fixed-output rows (seconds).
DEFAULT_TIMEOUT_SECONDS: Final = 30
#: Row 26: "sleeps past a 1 s timeout".
PROCESS_TIMEOUT_SECONDS: Final = 1
#: Row 25: "timeout 4 s, missing threshold 2 s".
HEARTBEAT_TIMEOUT_SECONDS: Final = 4

#: Row 19: the request snapshot lowers ``max_event_bytes`` to its floor.
OVERSIZED_LINE_LIMITS: Final = ProtocolLimits(
    max_event_bytes=MIN_EVENT_LINE_BYTES,
    max_manifest_bytes=MAX_RESULT_MANIFEST_BYTES,
    max_stderr_bytes=MAX_STDERR_BYTES,
    heartbeat_interval_seconds=PROTOCOL_LIMITS_DEFAULT.heartbeat_interval_seconds,
    missing_heartbeat_seconds=PROTOCOL_LIMITS_DEFAULT.missing_heartbeat_seconds,
)
#: Row 23: ``max_stderr_bytes`` lowered to 1 MiB.
STDERR_FLOOD_LIMITS: Final = ProtocolLimits(
    max_event_bytes=MAX_EVENT_LINE_BYTES,
    max_manifest_bytes=MAX_RESULT_MANIFEST_BYTES,
    max_stderr_bytes=MIN_STDERR_BYTES,
    heartbeat_interval_seconds=PROTOCOL_LIMITS_DEFAULT.heartbeat_interval_seconds,
    missing_heartbeat_seconds=PROTOCOL_LIMITS_DEFAULT.missing_heartbeat_seconds,
)
#: Rows 24 and 25: interval 1 s, missing threshold 2 s.
HEARTBEAT_LIMITS: Final = ProtocolLimits(
    max_event_bytes=MAX_EVENT_LINE_BYTES,
    max_manifest_bytes=MAX_RESULT_MANIFEST_BYTES,
    max_stderr_bytes=MAX_STDERR_BYTES,
    heartbeat_interval_seconds=1,
    missing_heartbeat_seconds=2,
)
#: Row 51: ``max_manifest_bytes`` lowered to its floor.
OVERSIZED_MANIFEST_LIMITS: Final = ProtocolLimits(
    max_event_bytes=MAX_EVENT_LINE_BYTES,
    max_manifest_bytes=MIN_RESULT_MANIFEST_BYTES,
    max_stderr_bytes=MAX_STDERR_BYTES,
    heartbeat_interval_seconds=PROTOCOL_LIMITS_DEFAULT.heartbeat_interval_seconds,
    missing_heartbeat_seconds=PROTOCOL_LIMITS_DEFAULT.missing_heartbeat_seconds,
)


@dataclass(frozen=True, slots=True, kw_only=True)
class Scenario:
    """One plan 11.2 row (or one entry of a multi-entry row) as expectations."""

    row: int
    name: str
    adapter_name: str
    command: CommandKind
    invocation_state: CommandInvocationState
    run_state: EngineRunState | None
    verdict: ReconciliationVerdict | None
    primary_code: str | None
    secondary_codes: tuple[str, ...] = ()
    #: The accepted ``RunEvent`` count where the row states it; ``None`` otherwise.
    accepted_events: int | None = None
    sanitized_manifest: bool = False
    semantic_status: SemanticStatus | None = None
    negotiation: NegotiationOutcome | None = None
    #: The native exit an ``EXITED`` row records; ``None`` where the child is killed.
    native_exit: int | None = None
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    limits: ProtocolLimits = PROTOCOL_LIMITS_DEFAULT
    cancel_after_first_heartbeat: bool = False
    #: Row 50: the harness re-seeds until the drawn token starts with a letter.
    letter_leading_token: bool = False

    @property
    def core_won(self) -> bool:
        """A terminal the core produced without reconciling the child's output."""
        return self.invocation_state in (
            _C.PROTOCOL_FAILED,
            _C.TIMED_OUT,
            _C.CANCELLED,
        )


def _describe(
    row: int,
    suffix: str,
    *,
    verdict: ReconciliationVerdict | None,
    primary_code: str | None,
    negotiation: NegotiationOutcome | None,
    **overrides: Any,
) -> Scenario:
    return Scenario(
        row=row,
        name=f"row{row:02d}-{suffix}-describe",
        adapter_name=f"fake.{suffix}",
        command=_K.DESCRIBE,
        invocation_state=overrides.pop("invocation_state", _C.EXITED),
        run_state=None,
        verdict=verdict,
        primary_code=primary_code,
        negotiation=negotiation,
        native_exit=overrides.pop("native_exit", 0),
        **overrides,
    )


def _validate(
    row: int,
    suffix: str,
    *,
    run_state: EngineRunState,
    verdict: ReconciliationVerdict | None,
    primary_code: str | None,
    native_exit: int | None = 0,
    **overrides: Any,
) -> Scenario:
    return Scenario(
        row=row,
        name=f"row{row:02d}-{suffix}-validate",
        adapter_name=f"fake.{suffix}",
        command=_K.VALIDATE,
        invocation_state=overrides.pop("invocation_state", _C.EXITED),
        run_state=run_state,
        verdict=verdict,
        primary_code=primary_code,
        native_exit=native_exit,
        **overrides,
    )


def _run(
    row: int,
    suffix: str,
    *,
    run_state: EngineRunState,
    verdict: ReconciliationVerdict | None,
    primary_code: str | None,
    native_exit: int | None = 0,
    **overrides: Any,
) -> Scenario:
    return Scenario(
        row=row,
        name=f"row{row:02d}-{suffix}-run",
        adapter_name=f"fake.{suffix}",
        command=_K.RUN,
        invocation_state=overrides.pop("invocation_state", _C.EXITED),
        run_state=run_state,
        verdict=verdict,
        primary_code=primary_code,
        native_exit=native_exit,
        **overrides,
    )


def _eligible(row: int, suffix: str, **overrides: Any) -> Scenario:
    """A run that reaches ``RESULT_FINALIZATION_ELIGIBLE`` and stays ``RUNNING``."""
    return _run(
        row,
        suffix,
        run_state=_R.RUNNING,
        verdict=_V.RESULT_FINALIZATION_ELIGIBLE,
        primary_code=None,
        sanitized_manifest=True,
        semantic_status=overrides.pop("semantic_status", _S.SUCCEEDED),
        **overrides,
    )


def _protocol_failed(row: int, suffix: str, code: str, **overrides: Any) -> Scenario:
    return _run(
        row,
        suffix,
        invocation_state=_C.PROTOCOL_FAILED,
        run_state=_R.FAILED,
        verdict=None,
        primary_code=code,
        native_exit=None,
        **overrides,
    )


def _exit_row(suffix: str, exit_value: int, code: str) -> Scenario:
    return _run(
        28,
        suffix,
        run_state=_R.FAILED,
        verdict=_V.FAILED,
        primary_code=code,
        native_exit=exit_value,
        accepted_events=2,
        sanitized_manifest=True,
        semantic_status={
            10: _S.FAILED,
            40: _S.FAILED,
            50: _S.CANCELLED,
            60: _S.TIMED_OUT,
            70: _S.FAILED,
        }[exit_value],
    )


#: Plan 11.2, one entry per behaviour, in row order.
SCENARIOS: Final[tuple[Scenario, ...]] = (
    _describe(
        1,
        "conformant",
        verdict=_V.DESCRIBED,
        primary_code=None,
        negotiation=NegotiationOutcome.NEGOTIATED,
    ),
    _validate(
        2,
        "conformant",
        run_state=_R.READY,
        verdict=_V.VALIDATED_READY,
        primary_code=None,
        accepted_events=2,
    ),
    _eligible(3, "conformant", accepted_events=5),
    _eligible(
        4, "warnings", accepted_events=6, semantic_status=_S.SUCCEEDED_WITH_WARNINGS
    ),
    _validate(
        5,
        "unsupported-capability",
        run_state=_R.NOT_APPLICABLE,
        verdict=_V.NOT_APPLICABLE,
        primary_code=COMPAT_NOT_APPLICABLE,
        native_exit=20,
    ),
    _run(
        6,
        "late-not-applicable",
        run_state=_R.NOT_APPLICABLE,
        verdict=_V.NOT_APPLICABLE,
        primary_code=COMPAT_LATE_NOT_APPLICABLE,
        native_exit=20,
        accepted_events=2,
        sanitized_manifest=True,
        semantic_status=_S.NOT_APPLICABLE,
    ),
    _validate(
        7,
        "temporarily-unavailable",
        run_state=_R.UNAVAILABLE,
        verdict=_V.UNAVAILABLE,
        primary_code=ADAPTER_UNAVAILABLE,
        native_exit=30,
    ),
    _run(
        8,
        "late-unavailable",
        run_state=_R.UNAVAILABLE,
        verdict=_V.UNAVAILABLE,
        primary_code=ADAPTER_UNAVAILABLE,
        native_exit=30,
        accepted_events=2,
        sanitized_manifest=True,
        semantic_status=_S.UNAVAILABLE,
    ),
    _validate(
        9,
        "validation-failure",
        run_state=_R.FAILED,
        verdict=_V.FAILED,
        primary_code=SCHEMA_REQUEST_INVALID,
        native_exit=10,
    ),
    _protocol_failed(10, "malformed-json", PROTOCOL_MALFORMED_JSONL, accepted_events=1),
    _protocol_failed(11, "unknown-event", PROTOCOL_MALFORMED_JSONL, accepted_events=0),
    _protocol_failed(
        12,
        "duplicate-sequence",
        PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
        accepted_events=2,
    ),
    _eligible(13, "replayed-sequence", accepted_events=6),
    _protocol_failed(
        14,
        "skipped-sequence",
        PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
        accepted_events=1,
    ),
    _protocol_failed(
        15,
        "wrong-invocation",
        PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
        accepted_events=0,
    ),
    _run(
        16,
        "wrong-request-hash",
        run_state=_R.FAILED,
        verdict=_V.FAILED,
        primary_code=ARTIFACT_RESULT_MANIFEST_INVALID,
        accepted_events=5,
    ),
    _protocol_failed(
        17, "wrong-token", PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION, accepted_events=0
    ),
    _validate(
        18,
        "wrong-token-proof",
        run_state=_R.FAILED,
        verdict=_V.FAILED,
        primary_code=PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
    ),
    _protocol_failed(
        19,
        "oversized-line",
        PROTOCOL_EVENT_TOO_LARGE,
        accepted_events=1,
        limits=OVERSIZED_LINE_LIMITS,
    ),
    _protocol_failed(
        20, "stdout-noise", PROTOCOL_STDOUT_CONTAMINATION, accepted_events=0
    ),
    _describe(
        21,
        "describe-noise",
        verdict=_V.DESCRIBE_UNAVAILABLE,
        primary_code=PROTOCOL_STDOUT_CONTAMINATION,
        negotiation=None,
    ),
    _eligible(22, "stderr-output", accepted_events=5),
    _eligible(
        23,
        "stderr-flood",
        accepted_events=5,
        secondary_codes=(PROCESS_STDERR_TRUNCATED,),
        limits=STDERR_FLOOD_LIMITS,
    ),
    _eligible(24, "heartbeat-success", limits=HEARTBEAT_LIMITS),
    _run(
        25,
        "heartbeat-timeout",
        invocation_state=_C.TIMED_OUT,
        run_state=_R.TIMED_OUT,
        verdict=None,
        primary_code=PROCESS_RUN_TIMED_OUT,
        secondary_codes=(PROCESS_MISSING_HEARTBEAT,),
        native_exit=None,
        accepted_events=1,
        timeout_seconds=HEARTBEAT_TIMEOUT_SECONDS,
        limits=HEARTBEAT_LIMITS,
    ),
    _describe(
        26,
        "process-timeout",
        invocation_state=_C.TIMED_OUT,
        verdict=None,
        primary_code=PROCESS_DESCRIBE_TIMED_OUT,
        negotiation=None,
        native_exit=None,
        timeout_seconds=PROCESS_TIMEOUT_SECONDS,
    ),
    _validate(
        26,
        "process-timeout",
        invocation_state=_C.TIMED_OUT,
        run_state=_R.TIMED_OUT,
        verdict=None,
        primary_code=PROCESS_VALIDATE_TIMED_OUT,
        native_exit=None,
        timeout_seconds=PROCESS_TIMEOUT_SECONDS,
    ),
    _run(
        26,
        "process-timeout",
        invocation_state=_C.TIMED_OUT,
        run_state=_R.TIMED_OUT,
        verdict=None,
        primary_code=PROCESS_RUN_TIMED_OUT,
        native_exit=None,
        timeout_seconds=PROCESS_TIMEOUT_SECONDS,
    ),
    _run(
        27,
        "cancellation",
        invocation_state=_C.CANCELLED,
        run_state=_R.CANCELLED,
        verdict=None,
        primary_code=PROCESS_CANCELLED,
        native_exit=None,
        cancel_after_first_heartbeat=True,
    ),
    _exit_row("exit-10-run", 10, SCHEMA_REQUEST_INVALID),
    _exit_row("exit-40", 40, ENGINE_RUNTIME_FAILURE),
    _exit_row("exit-50", 50, ENGINE_RUNTIME_FAILURE),
    _exit_row("exit-60", 60, ENGINE_RUNTIME_FAILURE),
    _exit_row("exit-70", 70, PROTOCOL_ADAPTER_REPORTED_VIOLATION),
    _run(
        29,
        "exit-unrecognized",
        run_state=_R.FAILED,
        verdict=_V.FAILED,
        primary_code=ENGINE_RUNTIME_FAILURE,
        secondary_codes=(PROCESS_UNRECOGNIZED_PROCESS_EXIT,),
        native_exit=3,
        accepted_events=1,
    ),
    _run(
        30,
        "missing-manifest",
        run_state=_R.FAILED,
        verdict=_V.FAILED,
        primary_code=ARTIFACT_RESULT_MANIFEST_INVALID,
        accepted_events=1,
    ),
    _run(
        31,
        "malformed-manifest",
        run_state=_R.FAILED,
        verdict=_V.FAILED,
        primary_code=ARTIFACT_RESULT_MANIFEST_INVALID,
        accepted_events=2,
    ),
    # Rows 32, 33, 36 and 41 fail at plan 9.2 check (13), (10) or (7) with a
    # consistent strict-valid manifest, which the reconciler keeps as evidence.
    _run(
        32,
        "disagreeing-manifest",
        run_state=_R.FAILED,
        verdict=_V.FAILED,
        primary_code=ARTIFACT_RESULT_MANIFEST_INVALID,
        native_exit=40,
        accepted_events=2,
        sanitized_manifest=True,
        semantic_status=_S.SUCCEEDED,
    ),
    _run(
        33,
        "exit-0-not-applicable",
        run_state=_R.FAILED,
        verdict=_V.FAILED,
        primary_code=ARTIFACT_RESULT_MANIFEST_INVALID,
        accepted_events=2,
        sanitized_manifest=True,
        semantic_status=_S.NOT_APPLICABLE,
    ),
    _protocol_failed(
        34, "path-escape", ARTIFACT_PATH_BOUNDARY_VIOLATION, accepted_events=1
    ),
    _run(
        35,
        "manifest-path-escape",
        run_state=_R.FAILED,
        verdict=_V.FAILED,
        primary_code=ARTIFACT_PATH_BOUNDARY_VIOLATION,
        accepted_events=4,
    ),
    _run(
        36,
        "checksum-mismatch",
        run_state=_R.FAILED,
        verdict=_V.FAILED,
        primary_code=ARTIFACT_VALIDATION_FAILED,
        accepted_events=5,
        sanitized_manifest=True,
        semantic_status=_S.SUCCEEDED,
    ),
    _run(
        37,
        "event-manifest-mismatch",
        run_state=_R.FAILED,
        verdict=_V.FAILED,
        primary_code=ARTIFACT_RESULT_MANIFEST_INVALID,
        accepted_events=5,
    ),
    _run(
        38,
        "crash-before-first-event",
        run_state=_R.FAILED,
        verdict=_V.FAILED,
        primary_code=ENGINE_RUNTIME_FAILURE,
        native_exit=40,
        accepted_events=0,
    ),
    _run(
        39,
        "crash-after-partial-events",
        run_state=_R.FAILED,
        verdict=_V.FAILED,
        primary_code=ENGINE_RUNTIME_FAILURE,
        native_exit=40,
        accepted_events=4,
    ),
    _eligible(
        40,
        "token-in-warning",
        accepted_events=6,
        semantic_status=_S.SUCCEEDED_WITH_WARNINGS,
    ),
    _run(
        41,
        "token-in-candidate",
        run_state=_R.FAILED,
        verdict=_V.FAILED,
        primary_code=SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
        accepted_events=5,
        sanitized_manifest=True,
        semantic_status=_S.SUCCEEDED,
    ),
    _protocol_failed(
        42, "core-namespace-code", PROTOCOL_MALFORMED_JSONL, accepted_events=0
    ),
    _describe(
        43,
        "describe-bad-version",
        verdict=_V.DESCRIBE_UNAVAILABLE,
        primary_code=PROTOCOL_UNSUPPORTED_VERSION,
        negotiation=None,
    ),
    _describe(
        44,
        "describe-no-common-version",
        verdict=_V.DESCRIBE_UNAVAILABLE,
        primary_code=ADAPTER_UNAVAILABLE,
        negotiation=NegotiationOutcome.FAILED,
    ),
    _protocol_failed(
        45,
        "second-final-result",
        PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
        accepted_events=3,
    ),
    _validate(
        46,
        "validate-emits-artifact",
        invocation_state=_C.PROTOCOL_FAILED,
        run_state=_R.FAILED,
        verdict=None,
        primary_code=PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
        native_exit=None,
        accepted_events=1,
    ),
    _validate(
        47,
        "stale-attempt-result",
        run_state=_R.FAILED,
        verdict=_V.FAILED,
        primary_code=PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
    ),
    _run(
        48,
        "partial-then-failed-manifest",
        run_state=_R.FAILED,
        verdict=_V.FAILED,
        primary_code=ENGINE_RUNTIME_FAILURE,
        native_exit=40,
        accepted_events=3,
        sanitized_manifest=True,
        semantic_status=_S.FAILED,
    ),
    _protocol_failed(
        49, "token-as-path", ARTIFACT_PATH_BOUNDARY_VIOLATION, accepted_events=1
    ),
    _protocol_failed(
        50,
        "token-as-phase",
        PROTOCOL_MALFORMED_JSONL,
        accepted_events=0,
        letter_leading_token=True,
    ),
    _run(
        51,
        "oversized-manifest",
        run_state=_R.FAILED,
        verdict=_V.FAILED,
        primary_code=ARTIFACT_RESULT_MANIFEST_INVALID,
        accepted_events=2,
        limits=OVERSIZED_MANIFEST_LIMITS,
    ),
    _protocol_failed(
        52, "invalid-utf8-stdout", PROTOCOL_STDOUT_CONTAMINATION, accepted_events=1
    ),
)

#: Plan 11.2: fifty-two rows; row 26 is three entries and row 28 five.
PLAN_ROW_COUNT: Final = 52
SCENARIO_ENTRY_COUNT: Final = 58


def describe_rows() -> tuple[Scenario, ...]:
    return tuple(item for item in SCENARIOS if item.command is _K.DESCRIBE)


def validate_rows() -> tuple[Scenario, ...]:
    return tuple(item for item in SCENARIOS if item.command is _K.VALIDATE)


def run_rows() -> tuple[Scenario, ...]:
    """The run rows that reach ``EXITED`` and are reconciled."""
    return tuple(
        item for item in SCENARIOS if item.command is _K.RUN and not item.core_won
    )


def protocol_failure_rows() -> tuple[Scenario, ...]:
    """The run rows the core terminalizes itself: protocol failure, deadline, cancel."""
    return tuple(item for item in SCENARIOS if item.command is _K.RUN and item.core_won)


def scenario_ids(rows: tuple[Scenario, ...]) -> tuple[str, ...]:
    return tuple(item.name for item in rows)


# --- Adapter-side verification vectors (plan 3.6, 11.2) -----------------------------


def _alter_payload_hash(document: dict[str, Any]) -> None:
    document["payload_hash"] = "f" * 64


def _alter_protocol_version(document: dict[str, Any]) -> None:
    document["protocol_version"] = "2.0.0"


def _relabel_as_validate(document: dict[str, Any]) -> None:
    document["command"] = "VALIDATE"


@dataclass(frozen=True, slots=True, kw_only=True)
class AdapterSideVector:
    """One tampered conformant request the fake must refuse with exit 10."""

    name: str
    command: CommandKind
    #: Mutates the decoded request document before the harness writes it.
    tamper: Callable[[dict[str, Any]], None] | None
    #: Replaces the ``--work-dir`` tail (relative to the command root) on launch.
    work_dir_tail: str | None = None

    @property
    def absence_detail(self) -> str:
        return "manifest_present" if self.command is _K.RUN else "output_present"


ADAPTER_SIDE_VECTORS: Final[tuple[AdapterSideVector, ...]] = (
    AdapterSideVector(
        name="payload-hash-run", command=_K.RUN, tamper=_alter_payload_hash
    ),
    AdapterSideVector(
        name="protocol-version-run", command=_K.RUN, tamper=_alter_protocol_version
    ),
    AdapterSideVector(
        name="validate-envelope-to-run", command=_K.RUN, tamper=_relabel_as_validate
    ),
    AdapterSideVector(
        name="work-dir-tail-run",
        command=_K.RUN,
        tamper=None,
        work_dir_tail="runs/elsewhere/work",
    ),
    AdapterSideVector(
        name="payload-hash-validate", command=_K.VALIDATE, tamper=_alter_payload_hash
    ),
)
