"""Stage 7 Task 2: the closed Stage 7 diagnostic table and factory (plan section 3.5).

The thirteen codes are asserted against their category, retry posture and severity
row by row; the hard-block column is proven to be exactly the Stage 5 category
partition of ``domain/retry.py``; the table is disjoint from the Stage 6 table and
meets the Stage 5 table in exactly the three core literals, which mint the identical
``Diagnostic`` through both factories; identity is content-only; every ``PROCESS.*``
code but the preflight rejection requires an invocation and that one accepts its
absence; and the module reads no clock and imports only ``domain`` and
``adapters.diagnostics``.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Mapping
from dataclasses import FrozenInstanceError, is_dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

import pytest
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.diagnostics import STAGE6_DIAGNOSTIC_CODES
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticSeverity,
)
from crypto_lab.domain.results import Failure
from crypto_lab.domain.retry import (
    HARD_BLOCKING_DIAGNOSTIC_CATEGORIES,
    RETRY_PERMITTING_DIAGNOSTIC_CATEGORIES,
)
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    IMMUTABLE_INPUT_MISMATCH,
    INVARIANT_VIOLATION,
    STAGE5_DIAGNOSTIC_CODES,
    stage5_diagnostic,
)
from crypto_lab.process_supervision import diagnostics as stage7
from crypto_lab.process_supervision.diagnostics import (
    PROCESS_CLEANUP_FAILED,
    PROCESS_PATH_PREFLIGHT_REJECTED,
    STAGE7_DIAGNOSTIC_CODES,
    Stage7DiagnosticPosture,
    stage7_diagnostic,
    stage7_failure,
)
from doubles.experiments import EXPERIMENT_ID, INSTANT, INVOCATION_ID, RUN_ID

_D = DiagnosticCategory
_S = DiagnosticSeverity
EXP: Final = EXPERIMENT_ID
RUN: Final = RUN_ID
INV: Final = INVOCATION_ID
SC: Final = "process_supervision.supervisor"
_INSTANT: Final = INSTANT
_CAUSE: Final = "diag_22345678-1234-4234-8234-123456789abc"
#: Plan section 3.5, read literally: code, category, retriable, severity, hard block.
#: The module constant carrying each code is the code with its dot replaced by an
#: underscore, the Stage 6 rule (``CORE.INVARIANT_VIOLATION`` ->
#: ``CORE_INVARIANT_VIOLATION``).
_TABLE: list[tuple[str, DiagnosticCategory, bool, DiagnosticSeverity, bool]] = [
    ("PROCESS.LAUNCH_FAILED", _D.ENGINE_RUNTIME, True, _S.ERROR, False),
    ("PROCESS.LAUNCH_NOT_COMMITTED", _D.ENGINE_RUNTIME, True, _S.ERROR, False),
    ("PROCESS.PATH_PREFLIGHT_REJECTED", _D.USER_CONFIGURATION, False, _S.ERROR, True),
    (
        "PROCESS.GRACEFUL_INTERRUPT_UNAVAILABLE",
        _D.ENGINE_RUNTIME,
        True,
        _S.WARNING,
        False,
    ),
    ("PROCESS.JOB_OBJECT_UNAVAILABLE", _D.ENGINE_RUNTIME, True, _S.WARNING, False),
    ("PROCESS.FORCED_TERMINATION", _D.ENGINE_RUNTIME, True, _S.WARNING, False),
    ("PROCESS.CLEANUP_FAILED", _D.ENGINE_RUNTIME, True, _S.ERROR, False),
    ("PROCESS.PID_REUSE_DETECTED", _D.ENGINE_RUNTIME, True, _S.WARNING, False),
    (
        "PROCESS.ORCHESTRATOR_RESTART_LOST_SUPERVISION",
        _D.ENGINE_RUNTIME,
        True,
        _S.ERROR,
        False,
    ),
    ("PROCESS.WRITE_BOUNDARY_VIOLATION", _D.ENGINE_RUNTIME, True, _S.WARNING, False),
    ("CORE.INVARIANT_VIOLATION", _D.INTERNAL_INVARIANT, False, _S.ERROR, True),
    ("CORE.IMMUTABLE_INPUT_MISMATCH", _D.INTERNAL_INVARIANT, False, _S.ERROR, True),
    ("PERSISTENCE.CONCURRENCY_CONFLICT", _D.PERSISTENCE, True, _S.ERROR, False),
]
_CODES = [row[0] for row in _TABLE]
_CORE_CODES = [code for code in _CODES if not code.startswith("PROCESS.")]
_INVOCATION_REQUIRED = [
    code
    for code in _CODES
    if code.startswith("PROCESS.") and code != "PROCESS.PATH_PREFLIGHT_REJECTED"
]
_INVOCATION_OPTIONAL = [code for code in _CODES if code not in _INVOCATION_REQUIRED]
#: The plan 2.6 import closure of ``diagnostics.py``.
_PURE_ROOTS = frozenset(
    {"__future__", "collections", "dataclasses", "datetime", "typing", "pydantic"}
)


def _mint(code: str, **overrides: object) -> Diagnostic:
    """Every correlation supplied, so any code in the table is constructible."""
    kwargs: dict[str, object] = {
        "source_component": SC,
        "timestamp_utc": _INSTANT,
        "experiment_id": EXP,
        "run_id": RUN,
        "invocation_id": INV,
        "details": {"os_error_code": 5},
        "causal_diagnostic_ids": (),
    }
    kwargs.update(overrides)
    return stage7_diagnostic(code, "the message", **kwargs)  # type: ignore[arg-type]


def _module_source() -> str:
    source = stage7.__file__
    assert source is not None
    return Path(source).read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# The plan's Step 1 sketches, verbatim
# --------------------------------------------------------------------------


def test_the_stage_seven_table_is_exactly_thirteen_rows_disjoint_from_stage_six() -> (
    None
):
    assert len(STAGE7_DIAGNOSTIC_CODES) == 13
    assert set(STAGE7_DIAGNOSTIC_CODES) & set(STAGE6_DIAGNOSTIC_CODES) == set()
    assert set(STAGE7_DIAGNOSTIC_CODES) & set(STAGE5_DIAGNOSTIC_CODES) == {
        INVARIANT_VIOLATION,
        IMMUTABLE_INPUT_MISMATCH,
        CONCURRENCY_CONFLICT,
    }


def test_a_stage_seven_core_literal_equals_the_stage_five_diagnostic() -> None:
    def mint(
        factory: Callable[..., Diagnostic],
    ) -> Diagnostic:  # explicit keywords: strict mypy rejects **dict[str, object]
        return factory(
            INVARIANT_VIOLATION,
            "m",
            source_component=SC,
            timestamp_utc=_INSTANT,
            experiment_id=EXP,
            run_id=RUN,
            invocation_id=INV,
            details={"k": 1},
        )

    assert mint(stage7_diagnostic) == mint(stage5_diagnostic)


def test_identity_is_content_only_and_every_process_code_requires_an_invocation() -> (
    None
):
    first = stage7_diagnostic(
        PROCESS_CLEANUP_FAILED,
        "m",
        invocation_id=INV,
        timestamp_utc=_INSTANT,
        source_component=SC,
    )
    later = stage7_diagnostic(
        PROCESS_CLEANUP_FAILED,
        "m",
        invocation_id=INV,
        timestamp_utc=_INSTANT + timedelta(1),
        source_component=SC,
    )
    assert first.diagnostic_id == later.diagnostic_id
    for code in (
        c
        for c in STAGE7_DIAGNOSTIC_CODES
        if c.startswith("PROCESS.") and c != PROCESS_PATH_PREFLIGHT_REJECTED
    ):
        with pytest.raises(ValueError, match="invocation_id"):
            stage7_diagnostic(code, "m", timestamp_utc=_INSTANT, source_component=SC)
    preflight = stage7_diagnostic(
        PROCESS_PATH_PREFLIGHT_REJECTED,
        "m",
        timestamp_utc=_INSTANT,
        source_component=SC,
    )
    assert not isinstance(
        preflight.invocation_id, str
    )  # MISSING; the one Failure-only code minted before an invocation exists (no
    # `is MISSING` on a typed field, §2.6)


# --------------------------------------------------------------------------
# The table, row by row
# --------------------------------------------------------------------------


def test_the_table_carries_exactly_the_thirteen_plan_rows_with_their_postures() -> None:
    assert isinstance(STAGE7_DIAGNOSTIC_CODES, Mapping)
    assert set(STAGE7_DIAGNOSTIC_CODES) == set(_CODES)
    assert len(set(_CODES)) == 13
    assert list(STAGE7_DIAGNOSTIC_CODES) == _CODES
    for code, category, retriable, severity, _hard in _TABLE:
        assert getattr(stage7, code.replace(".", "_")) == code
        posture = STAGE7_DIAGNOSTIC_CODES[code]
        assert type(posture) is Stage7DiagnosticPosture
        assert posture.category is category
        assert posture.retriable is retriable
        assert posture.severity is severity
    assert is_dataclass(Stage7DiagnosticPosture)
    with pytest.raises(FrozenInstanceError):
        STAGE7_DIAGNOSTIC_CODES[_CODES[0]].retriable = True  # type: ignore[misc]


def test_the_hard_block_column_is_the_stage_five_category_partition() -> None:
    """Plan 3.5's postures restate the Stage 5 retry partition (``domain/retry.py``),
    so a reclassified category would fail both."""
    for code, category, _retriable, _severity, hard in _TABLE:
        assert hard is (category in HARD_BLOCKING_DIAGNOSTIC_CATEGORIES), code
        assert (not hard) is (category in RETRY_PERMITTING_DIAGNOSTIC_CATEGORIES), code
    assert {row[1] for row in _TABLE} == {
        _D.ENGINE_RUNTIME,
        _D.USER_CONFIGURATION,
        _D.INTERNAL_INVARIANT,
        _D.PERSISTENCE,
    }


def test_the_three_core_literals_are_the_stage_five_constants_with_their_postures() -> (
    None
):
    assert stage7.CORE_INVARIANT_VIOLATION == INVARIANT_VIOLATION
    assert stage7.CORE_IMMUTABLE_INPUT_MISMATCH == IMMUTABLE_INPUT_MISMATCH
    assert stage7.PERSISTENCE_CONCURRENCY_CONFLICT == CONCURRENCY_CONFLICT
    assert set(_CORE_CODES) == {
        INVARIANT_VIOLATION,
        IMMUTABLE_INPUT_MISMATCH,
        CONCURRENCY_CONFLICT,
    }
    for code in _CORE_CODES:
        five = STAGE5_DIAGNOSTIC_CODES[code]
        seven = STAGE7_DIAGNOSTIC_CODES[code]
        assert (seven.category, seven.retriable) == (five.category, five.retriable)
        assert seven.severity is _S.ERROR
        kwargs: dict[str, object] = {
            "source_component": SC,
            "timestamp_utc": _INSTANT,
            "experiment_id": EXP,
            "run_id": RUN,
            "invocation_id": INV,
            "details": {"stored_revision": 3},
            "causal_diagnostic_ids": (_CAUSE,),
        }
        assert stage7_diagnostic(code, "same", **kwargs) == (  # type: ignore[arg-type]
            stage5_diagnostic(code, "same", **kwargs)  # type: ignore[arg-type]
        )
        bare = stage7_diagnostic(
            code, "bare", source_component=SC, timestamp_utc=_INSTANT
        )
        assert {"experiment_id", "run_id", "invocation_id"}.isdisjoint(
            bare.model_dump(mode="json")
        )


@pytest.mark.parametrize(
    "code",
    [
        *STAGE6_DIAGNOSTIC_CODES,
        *(code for code in STAGE5_DIAGNOSTIC_CODES if code not in _CORE_CODES),
        "PROCESS.NOPE",
        "process.launch_failed",
        "",
    ],
)
def test_a_code_outside_the_table_is_rejected(code: str) -> None:
    with pytest.raises(ValueError, match="not a Stage 7 code"):
        _mint(code)
    with pytest.raises(ValueError, match="not a Stage 7 code"):
        stage7_failure(code, "x", source_component=SC, timestamp_utc=_INSTANT)


# --------------------------------------------------------------------------
# The Diagnostic rules checked up front, both directions
# --------------------------------------------------------------------------


@pytest.mark.parametrize("code", _INVOCATION_REQUIRED)
def test_every_process_code_but_the_preflight_rejection_requires_an_invocation(
    code: str,
) -> None:
    with pytest.raises(ValueError, match="requires invocation_id"):
        _mint(code, invocation_id=MISSING)
    with pytest.raises(ValueError, match="requires invocation_id"):
        _mint(code, experiment_id=MISSING, run_id=MISSING, invocation_id=MISSING)
    minted = _mint(code)
    assert minted.invocation_id == INV
    assert minted.category is _D.ENGINE_RUNTIME
    describe = _mint(code, experiment_id=MISSING, run_id=MISSING)
    assert describe.invocation_id == INV
    assert {"experiment_id", "run_id"}.isdisjoint(describe.model_dump(mode="json"))


@pytest.mark.parametrize("code", _INVOCATION_OPTIONAL)
def test_the_preflight_rejection_and_the_core_literals_accept_an_absent_invocation(
    code: str,
) -> None:
    minted = _mint(code, invocation_id=MISSING)
    assert "invocation_id" not in minted.model_dump(mode="json")
    bare = _mint(code, experiment_id=MISSING, run_id=MISSING, invocation_id=MISSING)
    assert {"experiment_id", "run_id", "invocation_id"}.isdisjoint(
        bare.model_dump(mode="json")
    )
    correlated = _mint(code)
    assert (correlated.experiment_id, correlated.run_id, correlated.invocation_id) == (
        EXP,
        RUN,
        INV,
    )


def test_a_run_correlation_requires_an_experiment_correlation() -> None:
    with pytest.raises(ValueError, match="requires an experiment correlation"):
        _mint("PROCESS.LAUNCH_FAILED", experiment_id=MISSING)
    minted = _mint("PROCESS.LAUNCH_FAILED", run_id=MISSING)
    assert minted.experiment_id == EXP
    assert "run_id" not in minted.model_dump(mode="json")


@pytest.mark.parametrize(
    "details",
    [
        {"attempt_token": "a" * 32},
        {"attemptToken": "a" * 32},
        {"nested": {"Auth-Token": "x"}},
        {"api_key": "x"},
        {"customer_api_key": "x"},
    ],
)
def test_secret_like_detail_keys_are_rejected_before_identity_is_derived(
    details: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="secret-like") as captured:
        _mint("PROCESS.LAUNCH_FAILED", details=details)
    assert "a" * 32 not in str(captured.value)


@pytest.mark.parametrize(
    "details",
    [
        {"ratio": 0.5},
        {"count": 2**63},
        {"message": "x" * 2049},
        {"k": list(range(65))},
        {"groups": [{f"key{index}": index for index in range(64)} for _ in range(4)]},
        {"payload": ["x" * 2_048 for _ in range(8)]},
    ],
)
def test_unbounded_or_untyped_detail_values_are_rejected_by_name(
    details: dict[str, object],
) -> None:
    """Every ``Diagnostic.details`` rule, including the node and byte ceilings, is
    applied before hashing and names itself, never a validation error."""
    with pytest.raises(ValueError, match="diagnostic detail") as captured:
        _mint("PROCESS.LAUNCH_FAILED", details=details)
    assert type(captured.value) is ValueError


# --------------------------------------------------------------------------
# Posture, severity and identity
# --------------------------------------------------------------------------


@pytest.mark.parametrize(("code", "category", "retriable", "severity", "hard"), _TABLE)
def test_every_minted_diagnostic_takes_its_posture_from_the_table(
    code: str,
    category: DiagnosticCategory,
    retriable: bool,
    severity: DiagnosticSeverity,
    hard: bool,
) -> None:
    del hard
    minted = _mint(code, causal_diagnostic_ids=(_CAUSE,))
    assert minted.schema_version == "1.0.0"
    assert minted.error_code == code
    assert minted.category is category
    assert minted.retriable is retriable
    assert minted.severity is severity
    assert minted.message == "the message"
    assert minted.source_component == SC
    assert minted.timestamp_utc == _INSTANT
    assert minted.details == {"os_error_code": 5}
    assert minted.causal_diagnostic_ids == (_CAUSE,)
    assert minted.diagnostic_id.startswith("diag_")
    assert (minted.experiment_id, minted.run_id, minted.invocation_id) == (
        EXP,
        RUN,
        INV,
    )
    assert not isinstance(minted.engine, str)


def test_identity_is_a_function_of_content_alone() -> None:
    base = _mint("PROCESS.FORCED_TERMINATION")
    assert _mint("PROCESS.FORCED_TERMINATION") == base
    later = _mint(
        "PROCESS.FORCED_TERMINATION",
        timestamp_utc=datetime(2026, 9, 14, 12, 0, tzinfo=UTC),
    )
    assert later.diagnostic_id == base.diagnostic_id
    assert later.timestamp_utc != base.timestamp_utc
    variants = (
        stage7_diagnostic(
            "PROCESS.FORCED_TERMINATION",
            "another message",
            source_component=SC,
            timestamp_utc=_INSTANT,
            experiment_id=EXP,
            run_id=RUN,
            invocation_id=INV,
            details={"os_error_code": 5},
        ),
        _mint("PROCESS.FORCED_TERMINATION", details={"os_error_code": 6}),
        _mint("PROCESS.FORCED_TERMINATION", details={}),
        _mint(
            "PROCESS.FORCED_TERMINATION",
            source_component="process_supervision.reconciliation",
        ),
        _mint("PROCESS.FORCED_TERMINATION", run_id=MISSING),
        _mint("PROCESS.FORCED_TERMINATION", experiment_id=MISSING, run_id=MISSING),
        _mint("PROCESS.FORCED_TERMINATION", invocation_id=f"inv_2{INV[5:]}"),
        _mint("PROCESS.FORCED_TERMINATION", causal_diagnostic_ids=(_CAUSE,)),
        _mint("PROCESS.CLEANUP_FAILED"),
    )
    identities = {variant.diagnostic_id for variant in variants}
    assert base.diagnostic_id not in identities
    assert len(identities) == len(variants)


def test_details_default_to_an_empty_object_and_are_copied() -> None:
    supplied: dict[str, object] = {"os_error_code": 5}
    minted = _mint("PROCESS.CLEANUP_FAILED", details=supplied)
    supplied["os_error_code"] = 6
    assert minted.details == {"os_error_code": 5}
    absent = _mint("PROCESS.CLEANUP_FAILED", details=None)
    assert absent.details == {}
    assert absent.diagnostic_id != minted.diagnostic_id


def test_stage7_failure_wraps_exactly_the_stage7_diagnostic() -> None:
    failure = stage7_failure(
        PROCESS_PATH_PREFLIGHT_REJECTED,
        "command root exceeds the directory ceiling",
        source_component=SC,
        timestamp_utc=_INSTANT,
        details={
            "reason": "ceiling_exceeded",
            "path_length": 260,
            "ceiling": 247,
            "long_path_support": False,
        },
    )
    assert isinstance(failure, Failure)
    assert failure.outcome == "FAILURE"
    assert failure.diagnostics == (
        stage7_diagnostic(
            PROCESS_PATH_PREFLIGHT_REJECTED,
            "command root exceeds the directory ceiling",
            source_component=SC,
            timestamp_utc=_INSTANT,
            details={
                "reason": "ceiling_exceeded",
                "path_length": 260,
                "ceiling": 247,
                "long_path_support": False,
            },
        ),
    )
    assert failure.diagnostics[0].category is _D.USER_CONFIGURATION
    assert failure.diagnostics[0].retriable is False


# --------------------------------------------------------------------------
# Purity: no clock, the reviewed import closure, the exported surface
# --------------------------------------------------------------------------


def test_the_module_reads_no_clock_and_imports_only_domain_and_stage_six_codes() -> (
    None
):
    text = _module_source()
    for forbidden in (
        "datetime.now",
        "utcnow",
        "time.time",
        "now_utc(",
        "monotonic(",
        "import time",
        "import random",
        "random.",
        "uuid4(",
        "os.environ",
        "import subprocess",
        "import threading",
        "import doubles",
        "from doubles",
    ):
        assert forbidden not in text, forbidden
    roots: set[str] = set()
    project: set[str] = set()
    for node in ast.walk(ast.parse(text)):
        modules: list[str] = []
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            modules.append(node.module)
        for module in modules:
            root = module.partition(".")[0]
            if root == "crypto_lab":
                project.add(module)
            else:
                roots.add(root)
    assert roots <= _PURE_ROOTS, roots - _PURE_ROOTS
    for module in project:
        assert (
            module.startswith("crypto_lab.domain.")
            or module == "crypto_lab.adapters.diagnostics"
        ), module
    assert "crypto_lab.adapters.diagnostics" in project


def test_the_module_exports_the_table_the_factories_and_the_thirteen_constants() -> (
    None
):
    exported = stage7.__all__
    assert list(exported) == sorted(exported)
    assert len(set(exported)) == len(exported)
    assert set(exported) == {
        "STAGE7_DIAGNOSTIC_CODES",
        "Stage7DiagnosticPosture",
        "stage7_diagnostic",
        "stage7_failure",
        *(code.replace(".", "_") for code in _CODES),
    }
