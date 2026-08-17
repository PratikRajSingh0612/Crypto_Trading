"""Test the discriminated success-or-diagnostics ``Result`` value."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import TypeAdapter, ValidationError

from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticSeverity,
)
from crypto_lab.domain.results import Failure, Result, Success

_DIAGNOSTIC_ID = "diag_3f2504e0-4f89-41d3-9a0c-0305e82c3301"


def _diagnostic() -> Diagnostic:
    return Diagnostic(
        schema_version="1.0.0",
        diagnostic_id=_DIAGNOSTIC_ID,
        severity=DiagnosticSeverity.ERROR,
        error_code="STRATEGY.SOURCE_NOT_UTF8",
        category=DiagnosticCategory.SCHEMA_VALIDATION,
        message="source is not valid UTF-8",
        source_component="strategy.yaml_source",
        retriable=False,
        timestamp_utc=datetime(2026, 8, 16, tzinfo=UTC),
        details={},
        causal_diagnostic_ids=(),
    )


def test_success_carries_a_value_and_no_diagnostics() -> None:
    success = Success[int](outcome="SUCCESS", value=7)

    assert success.value == 7
    assert not hasattr(success, "diagnostics")


def test_failure_carries_diagnostics_and_no_value() -> None:
    failure = Failure(outcome="FAILURE", diagnostics=(_diagnostic(),))

    assert len(failure.diagnostics) == 1
    assert not hasattr(failure, "value")


def test_failure_rejects_an_empty_diagnostic_tuple() -> None:
    with pytest.raises(ValidationError):
        Failure(outcome="FAILURE", diagnostics=())


def test_result_discriminates_on_the_outcome_tag() -> None:
    adapter: TypeAdapter[Result[int]] = TypeAdapter(Result[int])

    success = adapter.validate_python({"outcome": "SUCCESS", "value": 7})
    failure = adapter.validate_python(
        {"outcome": "FAILURE", "diagnostics": (_diagnostic(),)},
    )

    assert isinstance(success, Success)
    assert isinstance(failure, Failure)


def test_result_rejects_a_value_carrying_both_outcomes() -> None:
    adapter: TypeAdapter[Result[int]] = TypeAdapter(Result[int])

    with pytest.raises(ValidationError):
        adapter.validate_python(
            {"outcome": "SUCCESS", "value": 7, "diagnostics": (_diagnostic(),)},
        )


def test_result_rejects_an_unknown_outcome_tag() -> None:
    adapter: TypeAdapter[Result[int]] = TypeAdapter(Result[int])

    with pytest.raises(ValidationError):
        adapter.validate_python({"outcome": "PARTIAL", "value": 7})
