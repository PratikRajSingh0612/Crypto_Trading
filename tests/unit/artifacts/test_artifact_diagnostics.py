"""Stage 9 Task 1: the ``ARTIFACT.*``/``SECURITY.*`` code table and its factory
(plan Task 1 "Interfaces produced"; plan 4.5; specification 21.2.1)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from crypto_lab.adapters.diagnostics import STAGE6_DIAGNOSTIC_CODES, stage6_diagnostic
from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_DIAGNOSTIC_CODES,
    ARTIFACT_FINALIZATION_TIMED_OUT,
    ARTIFACT_MOVE_FAILED,
    ARTIFACT_PATH_BOUNDARY_VIOLATION,
    ARTIFACT_QUARANTINE_OVERDUE,
    ARTIFACT_RESULT_MANIFEST_INVALID,
    ARTIFACT_SOURCE_COMPONENT,
    ARTIFACT_VALIDATION_FAILED,
    SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
    ArtifactDiagnosticPosture,
    artifact_diagnostic,
    artifact_failure,
)
from crypto_lab.domain.diagnostics import DiagnosticCategory, DiagnosticSeverity
from crypto_lab.domain.identifiers import validate_prefixed_uuid4
from crypto_lab.domain.retry import HARD_BLOCKING_DIAGNOSTIC_CATEGORIES

_EXP = "exp_12345678-1234-4234-8234-123456789abc"
_RUN = "run_12345678-1234-4234-8234-123456789abc"
_INV = "inv_12345678-1234-4234-8234-123456789abc"
_DIAG = "diag_12345678-1234-4234-8234-123456789abc"
_DIAG2 = "diag_22345678-1234-4234-8234-123456789abc"
_NOW = datetime(2026, 8, 10, 1, 2, 3, tzinfo=UTC)
_LATER = datetime(2026, 8, 10, 1, 2, 4, tzinfo=UTC)
_D = DiagnosticCategory
_S = DiagnosticSeverity

_SHARED = (
    ARTIFACT_RESULT_MANIFEST_INVALID,
    ARTIFACT_PATH_BOUNDARY_VIOLATION,
    ARTIFACT_VALIDATION_FAILED,
    SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
)
_HARD = (
    ARTIFACT_PATH_BOUNDARY_VIOLATION,
    ARTIFACT_VALIDATION_FAILED,
    SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
)


def test_codes_stable_and_within_category() -> None:
    assert ARTIFACT_RESULT_MANIFEST_INVALID == "ARTIFACT.RESULT_MANIFEST_INVALID"
    assert ARTIFACT_PATH_BOUNDARY_VIOLATION == "ARTIFACT.PATH_BOUNDARY_VIOLATION"
    assert ARTIFACT_VALIDATION_FAILED == "ARTIFACT.VALIDATION_FAILED"
    assert SECURITY_SENSITIVE_MATERIAL_LEAKAGE == "SECURITY.SENSITIVE_MATERIAL_LEAKAGE"
    assert ARTIFACT_FINALIZATION_TIMED_OUT == "ARTIFACT.FINALIZATION_TIMED_OUT"
    assert ARTIFACT_MOVE_FAILED == "ARTIFACT.MOVE_FAILED"
    assert ARTIFACT_QUARANTINE_OVERDUE == "ARTIFACT.QUARANTINE_OVERDUE"
    assert tuple(ARTIFACT_DIAGNOSTIC_CODES) == (
        *_SHARED,
        ARTIFACT_FINALIZATION_TIMED_OUT,
        ARTIFACT_MOVE_FAILED,
        ARTIFACT_QUARANTINE_OVERDUE,
    )
    assert len(ARTIFACT_DIAGNOSTIC_CODES) == 7
    categories = {
        code: posture.category for code, posture in ARTIFACT_DIAGNOSTIC_CODES.items()
    }
    assert categories == {
        ARTIFACT_RESULT_MANIFEST_INVALID: _D.ARTIFACT_CORRUPTION,
        ARTIFACT_PATH_BOUNDARY_VIOLATION: _D.ARTIFACT_CORRUPTION,
        ARTIFACT_VALIDATION_FAILED: _D.ARTIFACT_CORRUPTION,
        SECURITY_SENSITIVE_MATERIAL_LEAKAGE: _D.SECURITY,
        ARTIFACT_FINALIZATION_TIMED_OUT: _D.TIMEOUT,
        ARTIFACT_MOVE_FAILED: _D.PERSISTENCE,
        ARTIFACT_QUARANTINE_OVERDUE: _D.PERSISTENCE,
    }
    for code in ARTIFACT_DIAGNOSTIC_CODES:
        family, _, rest = code.partition(".")
        assert family in ("ARTIFACT", "SECURITY")
        assert rest
        assert rest.upper() == rest
    assert ARTIFACT_SOURCE_COMPONENT == "core.artifacts"
    assert isinstance(
        ARTIFACT_DIAGNOSTIC_CODES[ARTIFACT_MOVE_FAILED], ArtifactDiagnosticPosture
    )


def test_retriable_flags_match_table() -> None:
    """Specification 21.2.1: every row of the artifact family defaults to
    ``retriable=False``; the quarantine age check is a warning, the rest errors."""
    for code, posture in ARTIFACT_DIAGNOSTIC_CODES.items():
        assert posture.retriable is False, code
        expected = _S.WARNING if code == ARTIFACT_QUARANTINE_OVERDUE else _S.ERROR
        assert posture.severity is expected, code


def test_shared_codes_equal_the_stage6_posture() -> None:
    """One posture, not two: ``artifacts`` may not import ``adapters``, so the four
    Stage 6 literals are re-declared and pinned equal here (plan 4.5)."""
    for code in _SHARED:
        stage6 = STAGE6_DIAGNOSTIC_CODES[code]
        posture = ARTIFACT_DIAGNOSTIC_CODES[code]
        assert posture.category is stage6.category, code
        assert posture.retriable is stage6.retriable, code
        assert posture.severity is stage6.severity, code
        ours = artifact_diagnostic(
            code,
            message="shared posture",
            invocation_id=_INV,
            run_id=_RUN,
            experiment_id=_EXP,
            causal_ids=(_DIAG,),
            now_utc=_NOW,
        )
        theirs = stage6_diagnostic(
            code,
            "shared posture",
            source_component=ARTIFACT_SOURCE_COMPONENT,
            timestamp_utc=_NOW,
            experiment_id=_EXP,
            run_id=_RUN,
            invocation_id=_INV,
            causal_diagnostic_ids=(_DIAG,),
        )
        assert ours == theirs, code
    for code in (
        ARTIFACT_FINALIZATION_TIMED_OUT,
        ARTIFACT_MOVE_FAILED,
        ARTIFACT_QUARANTINE_OVERDUE,
    ):
        assert code not in STAGE6_DIAGNOSTIC_CODES


def test_hard_codes_are_category_blocked() -> None:
    for code in _HARD:
        category = ARTIFACT_DIAGNOSTIC_CODES[code].category
        assert category in HARD_BLOCKING_DIAGNOSTIC_CATEGORIES, code
    assert ARTIFACT_DIAGNOSTIC_CODES[ARTIFACT_MOVE_FAILED].category not in (
        HARD_BLOCKING_DIAGNOSTIC_CATEGORIES
    )
    assert ARTIFACT_DIAGNOSTIC_CODES[ARTIFACT_FINALIZATION_TIMED_OUT].category not in (
        HARD_BLOCKING_DIAGNOSTIC_CATEGORIES
    )
    assert ARTIFACT_DIAGNOSTIC_CODES[ARTIFACT_RESULT_MANIFEST_INVALID].category in (
        HARD_BLOCKING_DIAGNOSTIC_CATEGORIES
    )


def test_artifact_failure_builds_one_content_addressed_diagnostic() -> None:
    failure = artifact_failure(
        ARTIFACT_MOVE_FAILED,
        message="rename refused",
        invocation_id=_INV,
        run_id=_RUN,
        experiment_id=_EXP,
        causal_ids=(_DIAG, _DIAG2),
        now_utc=_NOW,
    )
    assert failure.outcome == "FAILURE"
    assert len(failure.diagnostics) == 1
    diagnostic = failure.diagnostics[0]
    validate_prefixed_uuid4(diagnostic.diagnostic_id, "diag_")
    assert diagnostic.error_code == ARTIFACT_MOVE_FAILED
    assert diagnostic.category is _D.PERSISTENCE
    assert diagnostic.retriable is False
    assert diagnostic.severity is _S.ERROR
    assert diagnostic.source_component == ARTIFACT_SOURCE_COMPONENT
    assert diagnostic.causal_diagnostic_ids == (_DIAG, _DIAG2)
    assert diagnostic.timestamp_utc == _NOW
    # Identity is a function of content, never of the clock instant (plan 10 replay).
    replay = artifact_failure(
        ARTIFACT_MOVE_FAILED,
        message="rename refused",
        invocation_id=_INV,
        run_id=_RUN,
        experiment_id=_EXP,
        causal_ids=(_DIAG, _DIAG2),
        now_utc=_LATER,
    ).diagnostics[0]
    assert replay.diagnostic_id == diagnostic.diagnostic_id
    assert replay.timestamp_utc == _LATER
    other = artifact_failure(
        ARTIFACT_MOVE_FAILED,
        message="rename refused twice",
        invocation_id=_INV,
        run_id=_RUN,
        experiment_id=_EXP,
        causal_ids=(_DIAG, _DIAG2),
        now_utc=_NOW,
    ).diagnostics[0]
    assert other.diagnostic_id != diagnostic.diagnostic_id
    # The owner-scoped forms: no correlation at all, or an experiment alone.
    bare = artifact_failure(ARTIFACT_QUARANTINE_OVERDUE, message="aged", now_utc=_NOW)
    assert bare.diagnostics[0].severity is _S.WARNING
    assert not isinstance(bare.diagnostics[0].invocation_id, str)
    assert not isinstance(bare.diagnostics[0].experiment_id, str)
    scoped = artifact_diagnostic(
        ARTIFACT_VALIDATION_FAILED, message="size", experiment_id=_EXP, now_utc=_NOW
    )
    assert scoped.experiment_id == _EXP


def test_artifact_factory_refuses_foreign_codes_and_missing_correlations() -> None:
    with pytest.raises(ValueError, match="not an artifact code"):
        artifact_diagnostic("PROCESS.CANCELLED", message="x", now_utc=_NOW)
    with pytest.raises(ValueError, match="requires invocation_id"):
        artifact_diagnostic(ARTIFACT_FINALIZATION_TIMED_OUT, message="x", now_utc=_NOW)
    with pytest.raises(ValueError, match="experiment correlation"):
        artifact_diagnostic(
            ARTIFACT_MOVE_FAILED, message="x", run_id=_RUN, now_utc=_NOW
        )
    with pytest.raises(ValueError, match="sorted"):
        artifact_diagnostic(
            ARTIFACT_MOVE_FAILED, message="x", causal_ids=(_DIAG2, _DIAG), now_utc=_NOW
        )
    assert (
        artifact_diagnostic(
            ARTIFACT_FINALIZATION_TIMED_OUT,
            message="deadline passed",
            invocation_id=_INV,
            now_utc=_NOW,
        ).category
        is _D.TIMEOUT
    )
