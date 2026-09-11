"""The per-command semantic exit table (Stage 6 plan section 9.1; specification 14.6,
21.2.1).

``process_exit_category_for`` (Stage 5) is the process fact: a native exit value maps
onto one of eight ``ProcessExitCategory`` members, every unrecognized value onto
``RUNTIME_FAILURE``. This module is the *semantic reading* of that fact for an
``EXITED`` invocation, total over ``CommandKind x ProcessExitCategory``; it defines no
second exit vocabulary and never infers a run state from an exit alone. ``EXITED``
is a process fact and does not imply semantic success (specification 14.6): exit ``0``
reads to no verdict-fixing code, and the output the command owes decides.

``SemanticExitReading`` is one cell (trust class P, unpublished): the process fact it
reads (``native_exit_value``, ``process_exit_category``, ``recognized``), whether the
command's output is required on that exit (``output_required`` -- true for ``DESCRIBE``
on exit ``0`` alone and for ``VALIDATE`` and ``RUN`` on ``0``, ``20`` and ``30``, the
single source of "output required" both reconcilers consult before any absence check),
the exit-derived ``diagnostic_code`` (``MISSING`` on exit ``0``), the ``verdict`` the
exit reads to when the output agrees with it and every later check passes
(``DESCRIBED``, ``VALIDATED_READY`` and ``RESULT_FINALIZATION_ELIGIBLE`` on exit
``0``), the ``run_target_state`` the exit alone fixes (``FAILED`` for the six failure
exits of a run-linked kind; ``MISSING`` where the output decides and always for
``DESCRIBE``), and the agreeing output shape: the ``ValidationOutcome`` a validation
result must declare to agree (``VALID``, ``INVALID``, ``NOT_APPLICABLE``,
``UNAVAILABLE`` on ``0``, ``10``, ``20``, ``30``; none on the other exits, where the
output is recorded and the code is the exit's), the non-``FAILED`` semantic statuses a
manifest may declare to agree (the two success statuses on ``0``, ``NOT_APPLICABLE``
on ``20``, ``UNAVAILABLE`` on ``30``, ``CANCELLED`` on ``50``, ``TIMED_OUT`` on
``60``), and ``declared_failure_code``, the code a manifest declaring ``FAILED`` reads
to: the exit's own code on a failure exit, ``ENGINE.RUNTIME_FAILURE`` on exit ``0``
(plan 9.1's truthful-declaration reading: the adapter declared the same non-success the
core would infer and nothing about the declaration is corrupt) and ``MISSING`` on
``20`` and ``30``, where a ``FAILED`` declaration contradicts the exit.

Declared readings recorded by the plan and applied here: an adapter's self-reported
exit ``50`` or ``60`` without a core cancellation or deadline is an engine runtime
failure (specification 17.1 reserves run ``CANCELLED`` and ``TIMED_OUT`` for core
wins); a describe carries no strategy, so its exit ``20`` is a runtime failure; the
unrecognized row carries ``recognized=False`` so the reconcilers cite the invocation's
mandatory ``PROCESS.UNRECOGNIZED_PROCESS_EXIT`` primary causally. Task-local readings:
a ``bool`` or any non-``int`` is refused by ``TypeError`` (the
``process_exit_category_for`` strictness -- a captured exit is never a flag); an
integer outside the ``NativeExitValue`` span is refused by ``ValueError``, because no
invocation record can carry it; every in-span unrecognized value, negative or
positive, is the "other" row. The function is pure and reads no clock, ambient
variable, filesystem, process or network state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self

from pydantic import model_validator
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.diagnostics import (
    ADAPTER_UNAVAILABLE,
    COMPAT_LATE_NOT_APPLICABLE,
    COMPAT_NOT_APPLICABLE,
    ENGINE_RUNTIME_FAILURE,
    PROTOCOL_ADAPTER_REPORTED_VIOLATION,
    SCHEMA_REQUEST_INVALID,
)
from crypto_lab.adapters.vocabulary import (
    ReconciliationVerdict,
    SemanticStatus,
    ValidationOutcome,
)
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.command_invocation import (
    MAX_NATIVE_EXIT_VALUE,
    MIN_NATIVE_EXIT_VALUE,
    NativeExitValue,
)
from crypto_lab.domain.diagnostics import ErrorCode
from crypto_lab.domain.engine_run import SUCCESS_ENGINE_RUN_STATES
from crypto_lab.domain.lifecycle import (
    RECOGNIZED_NATIVE_EXIT_VALUES,
    CommandKind,
    EngineRunState,
    ProcessExitCategory,
    process_exit_category_for,
)

_K = CommandKind
_C = ProcessExitCategory
_V = ReconciliationVerdict
_R = EngineRunState
_S = SemanticStatus
_O = ValidationOutcome


def _is_missing(value: object) -> bool:
    return value is MISSING


class SemanticExitReading(CanonicalModel):
    """One cell of the plan 9.1 table for one ``EXITED`` invocation (trust class P).

    A strict frozen projection with no envelope version (plan 3.1). The process
    fact is carried beside its reading so a consumer needs no second lookup; the
    validator keeps the fact self-consistent and refuses a success run target,
    because no exit ever fixes one (specification 14.6).
    """

    command_kind: CommandKind
    native_exit_value: NativeExitValue
    process_exit_category: ProcessExitCategory
    recognized: bool
    output_required: bool
    diagnostic_code: ErrorCode | MISSING = MISSING  # type: ignore[valid-type]
    verdict: ReconciliationVerdict | MISSING = MISSING  # type: ignore[valid-type]
    run_target_state: EngineRunState | MISSING = MISSING  # type: ignore[valid-type]
    agreeing_validation_outcome: ValidationOutcome | MISSING = MISSING  # type: ignore[valid-type]
    agreeing_semantic_statuses: tuple[SemanticStatus, ...]
    declared_failure_code: ErrorCode | MISSING = MISSING  # type: ignore[valid-type]

    @model_validator(mode="after")
    def validate_process_fact_and_target(self) -> Self:
        if self.process_exit_category is not process_exit_category_for(
            self.native_exit_value
        ):
            raise ValueError(
                "process_exit_category must equal "
                "process_exit_category_for(native_exit_value)"
            )
        if self.recognized is not (
            self.native_exit_value in RECOGNIZED_NATIVE_EXIT_VALUES
        ):
            raise ValueError(
                "recognized must state whether native_exit_value is a recognized "
                "exit value"
            )
        if (
            not _is_missing(self.run_target_state)
            and self.run_target_state in SUCCESS_ENGINE_RUN_STATES
        ):
            raise ValueError(
                "run_target_state is never a success state: no exit value fixes one"
            )
        return self


@dataclass(frozen=True, slots=True)
class _Cell:
    """The output-shaped part of one plan 9.1 cell; the process fact is added."""

    output_required: bool
    diagnostic_code: str | None
    verdict: ReconciliationVerdict
    run_target_state: EngineRunState | None = None
    agreeing_validation_outcome: ValidationOutcome | None = None
    agreeing_semantic_statuses: tuple[SemanticStatus, ...] = ()
    declared_failure_code: str | None = None


_SUCCESS_STATUSES: Final[tuple[SemanticStatus, ...]] = (
    _S.SUCCEEDED,
    _S.SUCCEEDED_WITH_WARNINGS,
)


def _describe(code: str | None, *, output_required: bool = False) -> _Cell:
    verdict = _V.DESCRIBED if code is None else _V.DESCRIBE_UNAVAILABLE
    return _Cell(output_required, code, verdict)


def _validate_failure(code: str) -> _Cell:
    return _Cell(False, code, _V.FAILED, _R.FAILED)


def _run_failure(code: str, *statuses: SemanticStatus) -> _Cell:
    return _Cell(
        False,
        code,
        _V.FAILED,
        _R.FAILED,
        agreeing_semantic_statuses=statuses,
        declared_failure_code=code,
    )


#: Plan 9.1, read literally: one cell per ``(CommandKind, ProcessExitCategory)``.
#: ``RUNTIME_FAILURE`` is both the exit-``40`` row and the "other" row, whose
#: only difference -- the causal reference -- is ``SemanticExitReading.recognized``.
_TABLE: Final[dict[tuple[CommandKind, ProcessExitCategory], _Cell]] = {
    (_K.DESCRIBE, _C.SUCCESS): _describe(None, output_required=True),
    (_K.DESCRIBE, _C.VALIDATION_FAILURE): _describe(SCHEMA_REQUEST_INVALID),
    (_K.DESCRIBE, _C.NOT_APPLICABLE): _describe(ENGINE_RUNTIME_FAILURE),
    (_K.DESCRIBE, _C.UNAVAILABLE): _describe(ADAPTER_UNAVAILABLE),
    (_K.DESCRIBE, _C.RUNTIME_FAILURE): _describe(ENGINE_RUNTIME_FAILURE),
    (_K.DESCRIBE, _C.CANCELLED): _describe(ENGINE_RUNTIME_FAILURE),
    (_K.DESCRIBE, _C.TIMED_OUT): _describe(ENGINE_RUNTIME_FAILURE),
    (_K.DESCRIBE, _C.PROTOCOL_VIOLATION): _describe(
        PROTOCOL_ADAPTER_REPORTED_VIOLATION
    ),
    (_K.VALIDATE, _C.SUCCESS): _Cell(
        True, None, _V.VALIDATED_READY, agreeing_validation_outcome=_O.VALID
    ),
    (_K.VALIDATE, _C.VALIDATION_FAILURE): _Cell(
        False,
        SCHEMA_REQUEST_INVALID,
        _V.FAILED,
        _R.FAILED,
        agreeing_validation_outcome=_O.INVALID,
    ),
    (_K.VALIDATE, _C.NOT_APPLICABLE): _Cell(
        True,
        COMPAT_NOT_APPLICABLE,
        _V.NOT_APPLICABLE,
        agreeing_validation_outcome=_O.NOT_APPLICABLE,
    ),
    (_K.VALIDATE, _C.UNAVAILABLE): _Cell(
        True,
        ADAPTER_UNAVAILABLE,
        _V.UNAVAILABLE,
        agreeing_validation_outcome=_O.UNAVAILABLE,
    ),
    (_K.VALIDATE, _C.RUNTIME_FAILURE): _validate_failure(ENGINE_RUNTIME_FAILURE),
    (_K.VALIDATE, _C.CANCELLED): _validate_failure(ENGINE_RUNTIME_FAILURE),
    (_K.VALIDATE, _C.TIMED_OUT): _validate_failure(ENGINE_RUNTIME_FAILURE),
    (_K.VALIDATE, _C.PROTOCOL_VIOLATION): _validate_failure(
        PROTOCOL_ADAPTER_REPORTED_VIOLATION
    ),
    (_K.RUN, _C.SUCCESS): _Cell(
        True,
        None,
        _V.RESULT_FINALIZATION_ELIGIBLE,
        agreeing_semantic_statuses=_SUCCESS_STATUSES,
        declared_failure_code=ENGINE_RUNTIME_FAILURE,
    ),
    (_K.RUN, _C.VALIDATION_FAILURE): _run_failure(SCHEMA_REQUEST_INVALID),
    (_K.RUN, _C.NOT_APPLICABLE): _Cell(
        True,
        COMPAT_LATE_NOT_APPLICABLE,
        _V.NOT_APPLICABLE,
        agreeing_semantic_statuses=(_S.NOT_APPLICABLE,),
    ),
    (_K.RUN, _C.UNAVAILABLE): _Cell(
        True,
        ADAPTER_UNAVAILABLE,
        _V.UNAVAILABLE,
        agreeing_semantic_statuses=(_S.UNAVAILABLE,),
    ),
    (_K.RUN, _C.RUNTIME_FAILURE): _run_failure(ENGINE_RUNTIME_FAILURE),
    (_K.RUN, _C.CANCELLED): _run_failure(ENGINE_RUNTIME_FAILURE, _S.CANCELLED),
    (_K.RUN, _C.TIMED_OUT): _run_failure(ENGINE_RUNTIME_FAILURE, _S.TIMED_OUT),
    (_K.RUN, _C.PROTOCOL_VIOLATION): _run_failure(PROTOCOL_ADAPTER_REPORTED_VIOLATION),
}


def _optional(value: object | None) -> object:
    return MISSING if value is None else value


def semantic_exit_reading(
    command_kind: CommandKind, native_exit_value: int
) -> SemanticExitReading:
    """Plan 9.1 as a total function over ``CommandKind`` x the native exit span.

    The process fact comes from ``process_exit_category_for``; the semantic cell
    from the closed table above. A ``bool`` or non-``int`` is a ``TypeError``, an
    integer outside the ``NativeExitValue`` span a ``ValueError``; every in-span
    unrecognized value is the "other" row with ``recognized=False``. Pure and
    deterministic over its two arguments.
    """
    if type(command_kind) is not CommandKind:
        raise TypeError("command kind must be a CommandKind member")
    if type(native_exit_value) is not int:
        raise TypeError("native exit value must be a built-in integer")
    if not MIN_NATIVE_EXIT_VALUE <= native_exit_value <= MAX_NATIVE_EXIT_VALUE:
        raise ValueError(
            "native exit value must be within the signed and unsigned 32-bit span "
            f"{MIN_NATIVE_EXIT_VALUE}..{MAX_NATIVE_EXIT_VALUE}"
        )
    category = process_exit_category_for(native_exit_value)
    cell = _TABLE[command_kind, category]
    return SemanticExitReading.model_validate(
        {
            "command_kind": command_kind,
            "native_exit_value": native_exit_value,
            "process_exit_category": category,
            "recognized": native_exit_value in RECOGNIZED_NATIVE_EXIT_VALUES,
            "output_required": cell.output_required,
            "diagnostic_code": _optional(cell.diagnostic_code),
            "verdict": cell.verdict,
            "run_target_state": _optional(cell.run_target_state),
            "agreeing_validation_outcome": _optional(cell.agreeing_validation_outcome),
            "agreeing_semantic_statuses": cell.agreeing_semantic_statuses,
            "declared_failure_code": _optional(cell.declared_failure_code),
        }
    )
