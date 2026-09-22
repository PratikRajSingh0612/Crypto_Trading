"""The closed Stage 8 diagnostic table and its ``Failure`` factory.

Plan section 2.5 reading 9: ``persistence/diagnostics.py`` defines the closed
table ``STAGE8_DIAGNOSTIC_CODES`` -- four ``PERSISTENCE.*`` codes plus
``CORE.INVARIANT_VIOLATION`` -- with the category and retry posture of each, and
``persistence_failure`` mints one content-identified diagnostic stamped from the
injected clock with ``source_component`` ``persistence``. The two codes shared
with Stage 5 are respelled literals (``persistence`` may not import
``experiments.diagnostics``) and are pinned equal to the Stage 5 constants here,
exactly as the Stage 7 table is pinned against the same constants.
"""

from __future__ import annotations

import pytest

from crypto_lab.domain.diagnostics import (
    DiagnosticCategory,
    DiagnosticDetailValue,
    DiagnosticSeverity,
)
from crypto_lab.domain.results import Failure
from crypto_lab.experiments import diagnostics as stage5
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    MIGRATION_MISMATCH,
    STAGE8_DIAGNOSTIC_CODES,
    STORAGE_UNAVAILABLE,
    WRITE_FAILED,
    persistence_failure,
)
from doubles.experiments import INSTANT, FixedClock


def test_the_stage_eight_code_table_is_closed_and_categorised() -> None:
    assert set(STAGE8_DIAGNOSTIC_CODES) == {
        "PERSISTENCE.CONCURRENCY_CONFLICT",
        "PERSISTENCE.WRITE_FAILED",
        "PERSISTENCE.MIGRATION_MISMATCH",
        "PERSISTENCE.STORAGE_UNAVAILABLE",
        "CORE.INVARIANT_VIOLATION",
    }
    for code, posture in STAGE8_DIAGNOSTIC_CODES.items():
        assert posture.category is (
            DiagnosticCategory.INTERNAL_INVARIANT
            if code.startswith("CORE.")
            else DiagnosticCategory.PERSISTENCE
        )


def test_the_respelled_codes_equal_the_stage_five_constants() -> None:
    """Reading 9: the two shared codes are literals pinned to Stage 5's constants."""
    assert CONCURRENCY_CONFLICT == stage5.CONCURRENCY_CONFLICT
    assert INVARIANT_VIOLATION == stage5.INVARIANT_VIOLATION
    for shared in (CONCURRENCY_CONFLICT, INVARIANT_VIOLATION):
        stage8_posture = STAGE8_DIAGNOSTIC_CODES[shared]
        stage5_posture = stage5.STAGE5_DIAGNOSTIC_CODES[shared]
        assert stage8_posture.category is stage5_posture.category
        assert stage8_posture.retriable is stage5_posture.retriable
    assert set(STAGE8_DIAGNOSTIC_CODES) & set(stage5.STAGE5_DIAGNOSTIC_CODES) == {
        CONCURRENCY_CONFLICT,
        INVARIANT_VIOLATION,
    }


def test_the_retry_postures_follow_reading_nine() -> None:
    assert (WRITE_FAILED, MIGRATION_MISMATCH, STORAGE_UNAVAILABLE) == (
        "PERSISTENCE.WRITE_FAILED",
        "PERSISTENCE.MIGRATION_MISMATCH",
        "PERSISTENCE.STORAGE_UNAVAILABLE",
    )
    assert {
        code: posture.retriable for code, posture in STAGE8_DIAGNOSTIC_CODES.items()
    } == {
        CONCURRENCY_CONFLICT: True,
        WRITE_FAILED: False,
        MIGRATION_MISMATCH: False,
        STORAGE_UNAVAILABLE: False,
        INVARIANT_VIOLATION: False,
    }


def test_persistence_failure_carries_exactly_one_stamped_diagnostic() -> None:
    details: dict[str, DiagnosticDetailValue] = {
        "sqlite_errorcode": 13,
        "sqlite_errorname": "SQLITE_FULL",
        "table": "probe",
        "operation": "insert",
    }

    failure = persistence_failure(
        WRITE_FAILED,
        message="the database is full",
        clock=FixedClock(INSTANT),
        details=details,
    )

    assert isinstance(failure, Failure)
    (diagnostic,) = failure.diagnostics
    assert diagnostic.error_code == WRITE_FAILED
    assert diagnostic.category is DiagnosticCategory.PERSISTENCE
    assert diagnostic.severity is DiagnosticSeverity.ERROR
    assert diagnostic.retriable is False
    assert diagnostic.source_component == "persistence"
    assert diagnostic.message == "the database is full"
    assert diagnostic.timestamp_utc == INSTANT
    assert diagnostic.details == details
    assert diagnostic.causal_diagnostic_ids == ()
    assert diagnostic.diagnostic_id.startswith("diag_")


def test_the_identity_is_a_function_of_content_not_of_the_instant() -> None:
    later = FixedClock(INSTANT)
    later.advance(60)

    first = persistence_failure(
        STORAGE_UNAVAILABLE, message="cannot open", clock=FixedClock(INSTANT)
    )
    second = persistence_failure(
        STORAGE_UNAVAILABLE, message="cannot open", clock=later
    )
    other = persistence_failure(
        STORAGE_UNAVAILABLE, message="cannot read", clock=FixedClock(INSTANT)
    )
    invariant = persistence_failure(
        INVARIANT_VIOLATION, message="cannot open", clock=FixedClock(INSTANT)
    )

    assert first.diagnostics[0].diagnostic_id == second.diagnostics[0].diagnostic_id
    assert first.diagnostics[0].timestamp_utc != second.diagnostics[0].timestamp_utc
    assert other.diagnostics[0].diagnostic_id != first.diagnostics[0].diagnostic_id
    assert invariant.diagnostics[0].diagnostic_id != first.diagnostics[0].diagnostic_id
    assert invariant.diagnostics[0].category is DiagnosticCategory.INTERNAL_INVARIANT
    assert first.diagnostics[0].details == {}


def test_the_factory_agrees_with_the_stage_five_factory_on_a_shared_code() -> None:
    """Two factories, one ``Diagnostic``: the identity payload is the Stage 5 one."""
    assert persistence_failure(
        CONCURRENCY_CONFLICT, message="row moved", clock=FixedClock(INSTANT)
    ) == stage5.stage5_failure(
        stage5.CONCURRENCY_CONFLICT,
        "row moved",
        source_component="persistence",
        timestamp_utc=INSTANT,
    )


def test_persistence_failure_refuses_a_code_outside_the_table() -> None:
    with pytest.raises(ValueError, match="is not a Stage 8 code"):
        persistence_failure(
            "PERSISTENCE.UNKNOWN", message="x", clock=FixedClock(INSTANT)
        )
    with pytest.raises(ValueError, match="is not a Stage 8 code"):
        persistence_failure(
            stage5.RETRY_DECISION_CONFLICT, message="x", clock=FixedClock(INSTANT)
        )


def test_persistence_failure_applies_the_diagnostic_detail_rules() -> None:
    with pytest.raises(ValueError, match="secret-like"):
        persistence_failure(
            WRITE_FAILED,
            message="x",
            clock=FixedClock(INSTANT),
            details={"attempt_token": "never"},
        )
    with pytest.raises(ValueError, match="too many nodes"):
        persistence_failure(
            WRITE_FAILED,
            message="x",
            clock=FixedClock(INSTANT),
            details={f"key_{index}": [0] * 60 for index in range(5)},
        )
    with pytest.raises(ValueError, match="maximum encoded bytes"):
        persistence_failure(
            WRITE_FAILED,
            message="x",
            clock=FixedClock(INSTANT),
            details={f"key_{index}": "v" * 2000 for index in range(10)},
        )
