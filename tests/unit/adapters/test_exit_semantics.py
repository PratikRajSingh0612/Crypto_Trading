"""Stage 6 Task 6: the per-command semantic exit table (Stage 6 plan section 9.1;
specification 14.6, 21.2.1).

`semantic_exit_reading` is the plan 9.1 table as a total function over
`CommandKind x native exit value`: the exit-derived diagnostic code, the verdict the
exit reads to when the output agrees, the run target the exit alone fixes, whether an
output is required, and the agreeing output shape. The process fact itself
(`ProcessExitCategory`) is Stage 5's `process_exit_category_for`, consumed and never
redefined; `EXITED` never implies semantic success, and exit `0` alone reads to no
verdict-fixing code.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Final

import pytest
from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab import adapters as adapters_package
from crypto_lab.adapters import exit_codes
from crypto_lab.adapters.diagnostics import (
    ADAPTER_UNAVAILABLE,
    COMPAT_LATE_NOT_APPLICABLE,
    COMPAT_NOT_APPLICABLE,
    ENGINE_RUNTIME_FAILURE,
    PROTOCOL_ADAPTER_REPORTED_VIOLATION,
    SCHEMA_REQUEST_INVALID,
    STAGE6_DIAGNOSTIC_CODES,
)
from crypto_lab.adapters.exit_codes import SemanticExitReading, semantic_exit_reading
from crypto_lab.adapters.vocabulary import (
    ReconciliationVerdict,
    SemanticStatus,
    ValidationOutcome,
)
from crypto_lab.domain.command_invocation import (
    MAX_NATIVE_EXIT_VALUE,
    MIN_NATIVE_EXIT_VALUE,
)
from crypto_lab.domain.engine_run import SUCCESS_ENGINE_RUN_STATES
from crypto_lab.domain.lifecycle import (
    RECOGNIZED_NATIVE_EXIT_VALUES,
    CommandKind,
    EngineRunState,
    ProcessExitCategory,
    process_exit_category_for,
)

_K = CommandKind
_V = ReconciliationVerdict
_R = EngineRunState
_S = SemanticStatus
_O = ValidationOutcome
_C = ProcessExitCategory

_FIELDS: Final = (
    "command_kind",
    "native_exit_value",
    "process_exit_category",
    "recognized",
    "output_required",
    "diagnostic_code",
    "verdict",
    "run_target_state",
    "agreeing_validation_outcome",
    "agreeing_semantic_statuses",
    "declared_failure_code",
)
_OPTIONAL: Final = (
    "diagnostic_code",
    "verdict",
    "run_target_state",
    "agreeing_validation_outcome",
    "declared_failure_code",
)
_RECOGNIZED: Final = (0, 10, 20, 30, 40, 50, 60, 70)
#: Unknown negative and positive values, each the "other" row of plan 9.1.
_UNRECOGNIZED: Final = (-1, 1, 3, 255, 71, MIN_NATIVE_EXIT_VALUE, MAX_NATIVE_EXIT_VALUE)
_PURE_ROOTS: Final = frozenset(
    {"__future__", "dataclasses", "typing", "pydantic", "crypto_lab"}
)
_STAGE4_BARE_NAMES: Final = frozenset(
    {"buffer", "context", "note", "problem", "compose", "Loader", "get_snippet"}
)
_SUCCESS_STATUSES: Final = (_S.SUCCEEDED, _S.SUCCEEDED_WITH_WARNINGS)
# Short aliases so every literal row of the table below fits one line.
_SRI: Final = SCHEMA_REQUEST_INVALID
_ERF: Final = ENGINE_RUNTIME_FAILURE
_AU: Final = ADAPTER_UNAVAILABLE
_PARV: Final = PROTOCOL_ADAPTER_REPORTED_VIOLATION
_CNA: Final = COMPAT_NOT_APPLICABLE
_CLNA: Final = COMPAT_LATE_NOT_APPLICABLE
_DU: Final = _V.DESCRIBE_UNAVAILABLE
_VR: Final = _V.VALIDATED_READY
_RFE: Final = _V.RESULT_FINALIZATION_ELIGIBLE
_NA: Final = _V.NOT_APPLICABLE
_UN: Final = _V.UNAVAILABLE
_F: Final = _V.FAILED
_RF: Final = _R.FAILED
_ONA: Final = _O.NOT_APPLICABLE
_OUN: Final = _O.UNAVAILABLE
_SNA: Final = (_S.NOT_APPLICABLE,)
_SUN: Final = (_S.UNAVAILABLE,)
_SC: Final = (_S.CANCELLED,)
_ST: Final = (_S.TIMED_OUT,)

#: Plan 9.1, read literally, one row per cell: (kind, exit) -> (output_required,
#: diagnostic_code, verdict, run_target_state, agreeing_validation_outcome,
#: agreeing_semantic_statuses, declared_failure_code). ``None`` reads MISSING.
_CELLS: Final[dict[tuple[CommandKind, int | None], tuple[Any, ...]]] = {
    (_K.DESCRIBE, 0): (True, None, _V.DESCRIBED, None, None, (), None),
    (_K.DESCRIBE, 10): (False, _SRI, _DU, None, None, (), None),
    (_K.DESCRIBE, 20): (False, _ERF, _DU, None, None, (), None),
    (_K.DESCRIBE, 30): (False, _AU, _DU, None, None, (), None),
    (_K.DESCRIBE, 40): (False, _ERF, _DU, None, None, (), None),
    (_K.DESCRIBE, 50): (False, _ERF, _DU, None, None, (), None),
    (_K.DESCRIBE, 60): (False, _ERF, _DU, None, None, (), None),
    (_K.DESCRIBE, 70): (False, _PARV, _DU, None, None, (), None),
    (_K.DESCRIBE, None): (False, _ERF, _DU, None, None, (), None),
    (_K.VALIDATE, 0): (True, None, _VR, None, _O.VALID, (), None),
    (_K.VALIDATE, 10): (False, _SRI, _F, _RF, _O.INVALID, (), None),
    (_K.VALIDATE, 20): (True, _CNA, _NA, None, _ONA, (), None),
    (_K.VALIDATE, 30): (True, _AU, _UN, None, _OUN, (), None),
    (_K.VALIDATE, 40): (False, _ERF, _F, _RF, None, (), None),
    (_K.VALIDATE, 50): (False, _ERF, _F, _RF, None, (), None),
    (_K.VALIDATE, 60): (False, _ERF, _F, _RF, None, (), None),
    (_K.VALIDATE, 70): (False, _PARV, _F, _RF, None, (), None),
    (_K.VALIDATE, None): (False, _ERF, _F, _RF, None, (), None),
    (_K.RUN, 0): (True, None, _RFE, None, None, _SUCCESS_STATUSES, _ERF),
    (_K.RUN, 10): (False, _SRI, _F, _RF, None, (), _SRI),
    (_K.RUN, 20): (True, _CLNA, _NA, None, None, _SNA, None),
    (_K.RUN, 30): (True, _AU, _UN, None, None, _SUN, None),
    (_K.RUN, 40): (False, _ERF, _F, _RF, None, (), _ERF),
    (_K.RUN, 50): (False, _ERF, _F, _RF, None, _SC, _ERF),
    (_K.RUN, 60): (False, _ERF, _F, _RF, None, _ST, _ERF),
    (_K.RUN, 70): (False, _PARV, _F, _RF, None, (), _PARV),
    (_K.RUN, None): (False, _ERF, _F, _RF, None, (), _ERF),
}
#: Plan 9.3: the run target of each verdict, mirrored for the reading's consistency.
_TARGET_OF_VERDICT: Final = {
    _V.DESCRIBED: None,
    _V.DESCRIBE_UNAVAILABLE: None,
    _V.VALIDATED_READY: _R.READY,
    _V.NOT_APPLICABLE: _R.NOT_APPLICABLE,
    _V.UNAVAILABLE: _R.UNAVAILABLE,
    _V.FAILED: _R.FAILED,
    _V.RESULT_FINALIZATION_ELIGIBLE: None,
}


def _missing(value: object) -> bool:
    return value is MISSING


def _optional(value: object) -> object:
    return MISSING if value is None else value


def _cell(kind: CommandKind, exit_value: int) -> tuple[Any, ...]:
    key = exit_value if exit_value in RECOGNIZED_NATIVE_EXIT_VALUES else None
    return _CELLS[kind, key]


_EVERY_CELL: Final = [
    (kind, exit_value)
    for kind in CommandKind
    for exit_value in (*_RECOGNIZED, *_UNRECOGNIZED)
]


# --- Inventory, shape and purity ------------------------------------------------------


def test_the_package_exports_the_exit_semantics_surface() -> None:
    exported = adapters_package.__all__
    assert {"SemanticExitReading", "semantic_exit_reading"} <= set(exported)
    assert "_CELLS" not in exported


def test_the_reading_declares_exactly_the_ledger_fields_in_order() -> None:
    assert tuple(SemanticExitReading.model_fields) == _FIELDS
    for name, field in SemanticExitReading.model_fields.items():
        assert field.is_required() is (name not in _OPTIONAL), name
    # Trust class P (plan 3.1): unpublished, no envelope version.
    assert "schema_version" not in SemanticExitReading.model_fields
    assert "protocol_version" not in SemanticExitReading.model_fields


def test_the_table_covers_every_cell_of_plan_nine_one() -> None:
    """Three kinds times nine rows: the eight recognized values and the other row."""
    assert len(_CELLS) == 27
    assert {kind for kind, _ in _CELLS} == set(CommandKind)
    for kind in CommandKind:
        rows = {exit_value for owner, exit_value in _CELLS if owner is kind}
        assert rows == {*_RECOGNIZED, None}
    assert frozenset(_RECOGNIZED) == RECOGNIZED_NATIVE_EXIT_VALUES


def _scan(source: str) -> tuple[set[str], set[str], set[str]]:
    tree = ast.parse(source)
    roots: set[str] = set()
    packages: set[str] = set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.partition(".")[0])
            if node.module.startswith("crypto_lab."):
                packages.add(node.module.split(".")[1])
        elif isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        if isinstance(node, ast.Call):
            target = node.func
            called = (
                target.id
                if isinstance(target, ast.Name)
                else getattr(target, "attr", "")
            )
            assert called not in {"open", "now", "utcnow", "today"}, ast.dump(node)
    return roots, packages, names


def test_the_module_imports_only_pure_roots_and_defines_no_second_exit_enum() -> None:
    source = Path(exit_codes.__file__ or "").read_text(encoding="utf-8")
    roots, packages, names = _scan(source)
    assert roots <= _PURE_ROOTS, sorted(roots - _PURE_ROOTS)
    assert packages <= {"domain", "adapters"}, sorted(packages)
    assert names & _STAGE4_BARE_NAMES == set()
    for forbidden in ("subprocess", "os.", "time.", "random", "environ"):
        assert forbidden not in source
    tree = ast.parse(source)
    enums = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        and any(getattr(base, "id", "") == "StrEnum" for base in node.bases)
    }
    assert enums == set()
    defined = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef | ast.FunctionDef)
    }
    assert defined & {"CommandResult", "ProcessSupervisor", "RunManifest"} == set()


def test_the_bare_name_scan_finds_a_planted_name() -> None:
    planted = "Loader = compose(problem)\n"
    assert _scan(planted)[2] & _STAGE4_BARE_NAMES == {"Loader", "compose", "problem"}
    with pytest.raises(AssertionError):
        _scan("value = now()\n")


# --- Every cell ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "exit_value"),
    _EVERY_CELL,
    ids=[f"{kind.value}-{exit_value}" for kind, exit_value in _EVERY_CELL],
)
def test_every_cell_of_the_table_reads_exactly_as_plan_nine_one(
    kind: CommandKind, exit_value: int
) -> None:
    (
        output_required,
        code,
        verdict,
        run_target,
        agreeing_outcome,
        agreeing_statuses,
        declared_failure_code,
    ) = _cell(kind, exit_value)
    reading = semantic_exit_reading(kind, exit_value)
    assert reading.command_kind is kind
    assert reading.native_exit_value == exit_value
    assert reading.process_exit_category is process_exit_category_for(exit_value)
    assert reading.recognized is (exit_value in RECOGNIZED_NATIVE_EXIT_VALUES)
    assert reading.output_required is output_required
    assert reading.diagnostic_code == _optional(code)
    assert reading.verdict == _optional(verdict)
    assert reading.run_target_state == _optional(run_target)
    assert reading.agreeing_validation_outcome == _optional(agreeing_outcome)
    assert reading.agreeing_semantic_statuses == agreeing_statuses
    assert reading.declared_failure_code == _optional(declared_failure_code)


@pytest.mark.parametrize(
    ("kind", "exit_value"),
    _EVERY_CELL,
    ids=[f"{kind.value}-{exit_value}" for kind, exit_value in _EVERY_CELL],
)
def test_every_reading_is_internally_consistent_and_never_a_success_state(
    kind: CommandKind, exit_value: int
) -> None:
    reading = semantic_exit_reading(kind, exit_value)
    # Exit 0 alone fixes no code: the output decides (specification 14.6).
    assert _missing(reading.diagnostic_code) is (exit_value == 0)
    if not _missing(reading.diagnostic_code):
        assert reading.diagnostic_code in STAGE6_DIAGNOSTIC_CODES
    assert not _missing(reading.verdict)
    # The run target is fixed by the exit alone exactly for a FAILED verdict of a
    # run-linked kind; it is otherwise decided by the output (plan 9.1).
    expected_target = (
        _R.FAILED
        if kind is not _K.DESCRIBE and reading.verdict is _V.FAILED
        else MISSING
    )
    assert reading.run_target_state == expected_target
    if not _missing(reading.run_target_state):
        assert reading.run_target_state not in SUCCESS_ENGINE_RUN_STATES
        assert _TARGET_OF_VERDICT[reading.verdict] is reading.run_target_state
    if kind is _K.DESCRIBE:
        assert reading.verdict in {_V.DESCRIBED, _V.DESCRIBE_UNAVAILABLE}
        assert _missing(reading.agreeing_validation_outcome)
        assert reading.agreeing_semantic_statuses == ()
        assert _missing(reading.declared_failure_code)
    elif kind is _K.VALIDATE:
        assert reading.agreeing_semantic_statuses == ()
        assert _missing(reading.declared_failure_code)
    else:
        assert _missing(reading.agreeing_validation_outcome)
        assert _S.FAILED not in reading.agreeing_semantic_statuses
        assert _missing(reading.declared_failure_code) is (exit_value in {20, 30})
    if not reading.recognized:
        assert reading.process_exit_category is _C.RUNTIME_FAILURE
        assert reading.diagnostic_code == ENGINE_RUNTIME_FAILURE


def test_output_required_is_true_exactly_for_the_plan_nine_one_cells() -> None:
    required = {
        (kind, exit_value)
        for kind, exit_value in _EVERY_CELL
        if semantic_exit_reading(kind, exit_value).output_required
    }
    assert required == {
        (_K.DESCRIBE, 0),
        (_K.VALIDATE, 0),
        (_K.VALIDATE, 20),
        (_K.VALIDATE, 30),
        (_K.RUN, 0),
        (_K.RUN, 20),
        (_K.RUN, 30),
    }


def test_every_recognized_value_maps_exactly_once_and_distinctly() -> None:
    for kind in CommandKind:
        readings = [semantic_exit_reading(kind, value) for value in _RECOGNIZED]
        categories = [reading.process_exit_category for reading in readings]
        assert len(set(categories)) == len(_RECOGNIZED) == len(_C)
        assert all(reading.recognized for reading in readings)


@pytest.mark.parametrize("exit_value", _UNRECOGNIZED)
def test_unknown_negative_and_positive_values_are_the_other_row(
    exit_value: int,
) -> None:
    for kind in CommandKind:
        reading = semantic_exit_reading(kind, exit_value)
        assert reading.recognized is False
        assert reading.process_exit_category is _C.RUNTIME_FAILURE
        assert reading.diagnostic_code == ENGINE_RUNTIME_FAILURE
        assert reading.output_required is False
        assert reading.native_exit_value == exit_value
        other = semantic_exit_reading(kind, 3)
        assert reading.model_dump(exclude={"native_exit_value"}) == other.model_dump(
            exclude={"native_exit_value"}
        )


# --- Strictness ---------------------------------------------------------------------


@pytest.mark.parametrize("value", [True, False, "0", 0.0, None, b"0", 40.0])
def test_a_non_integer_exit_value_is_refused_by_type(value: object) -> None:
    for kind in CommandKind:
        with pytest.raises(TypeError, match="built-in integer"):
            semantic_exit_reading(kind, value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "value", [MIN_NATIVE_EXIT_VALUE - 1, MAX_NATIVE_EXIT_VALUE + 1, 2**64]
)
def test_an_exit_value_outside_the_native_span_is_refused(value: int) -> None:
    for kind in CommandKind:
        with pytest.raises(ValueError, match="native exit"):
            semantic_exit_reading(kind, value)


@pytest.mark.parametrize("kind", ["RUN", "run", 0, None, ProcessExitCategory.SUCCESS])
def test_a_non_member_command_kind_is_refused(kind: object) -> None:
    with pytest.raises(TypeError, match="CommandKind"):
        semantic_exit_reading(kind, 0)  # type: ignore[arg-type]


def test_the_reading_is_frozen_strict_and_closed() -> None:
    reading = semantic_exit_reading(_K.RUN, 0)
    with pytest.raises(ValidationError, match="frozen"):
        reading.output_required = False
    payload = reading.model_dump(mode="python")
    with pytest.raises(ValidationError, match="extra_forbidden"):
        SemanticExitReading.model_validate({**payload, "success": True})
    with pytest.raises(ValidationError, match="output_required"):
        SemanticExitReading.model_validate({**payload, "output_required": "yes"})
    with pytest.raises(ValidationError, match="native_exit_value"):
        SemanticExitReading.model_validate({**payload, "native_exit_value": True})
    with pytest.raises(ValidationError, match="native_exit_value"):
        SemanticExitReading.model_validate({**payload, "native_exit_value": "0"})
    with pytest.raises(ValidationError, match="run_target_state"):
        SemanticExitReading.model_validate(
            {**payload, "run_target_state": _R.SUCCEEDED}
        )
    with pytest.raises(ValidationError, match="diagnostic_code"):
        SemanticExitReading.model_validate({**payload, "diagnostic_code": "not a code"})
    assert SemanticExitReading.model_validate(payload) == reading


def test_the_reading_rejects_an_inconsistent_process_fact() -> None:
    """Preventive (began green): the validator keeps the process fact self-consistent
    with Stage 5's mapping, so a hand-built reading cannot misstate it."""
    payload = semantic_exit_reading(_K.RUN, 0).model_dump(mode="python")
    with pytest.raises(ValidationError, match="process_exit_category"):
        SemanticExitReading.model_validate(
            {**payload, "process_exit_category": _C.CANCELLED}
        )
    with pytest.raises(ValidationError, match="recognized"):
        SemanticExitReading.model_validate({**payload, "recognized": False})
    other = semantic_exit_reading(_K.RUN, 3).model_dump(mode="python")
    with pytest.raises(ValidationError, match="recognized"):
        SemanticExitReading.model_validate({**other, "recognized": True})


def test_the_reading_is_deterministic_and_reads_nothing_ambient(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("semantic_exit_reading performed runtime work")

    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("os.getenv", forbidden)
    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr("time.monotonic", forbidden)
    monkeypatch.setattr("random.random", forbidden)
    for kind, exit_value in _EVERY_CELL:
        first = semantic_exit_reading(kind, exit_value)
        second = semantic_exit_reading(kind, exit_value)
        assert first == second
        assert first.model_dump_json() == second.model_dump_json()
