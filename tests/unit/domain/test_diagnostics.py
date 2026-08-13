from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

import pytest
from pydantic import ValidationError

from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticDetailValue,
    DiagnosticSeverity,
)

_DIAGNOSTIC_ID = "diag_12345678-1234-4234-8234-123456789abc"
_CAUSE_ID = "diag_22345678-1234-4234-8234-123456789abc"


def _diagnostic(
    *,
    details: dict[str, object] | None = None,
    causes: tuple[str, ...] = (),
) -> Diagnostic:
    return Diagnostic(
        schema_version="1.0.0",
        diagnostic_id=_DIAGNOSTIC_ID,
        severity=DiagnosticSeverity.ERROR,
        error_code="CONFIG.LAYER_INVALID",
        category=DiagnosticCategory.USER_CONFIGURATION,
        message="Configuration layer is invalid.",
        source_component="configuration.loader",
        retriable=False,
        timestamp_utc=datetime(2026, 8, 10, tzinfo=UTC),
        details=cast(
            dict[str, DiagnosticDetailValue],
            {} if details is None else details,
        ),
        causal_diagnostic_ids=causes,
    )


def test_diagnostic_round_trip_and_optional_correlations() -> None:
    diagnostic = _diagnostic(details={"path_kind": "primary", "attempt": 1})
    assert Diagnostic.model_validate_json(diagnostic.model_dump_json()) == diagnostic
    dumped = diagnostic.model_dump(mode="json")
    for field in ("experiment_id", "run_id", "invocation_id", "engine"):
        assert field not in dumped


@pytest.mark.parametrize(
    "field",
    ["experiment_id", "run_id", "invocation_id", "engine"],
)
def test_optional_correlations_reject_explicit_null(field: str) -> None:
    payload = _diagnostic().model_dump(mode="python")
    payload[field] = None
    with pytest.raises(ValidationError):
        Diagnostic.model_validate(payload)


@pytest.mark.parametrize(
    "error_code",
    ["invalid", "CONFIG", "CONFIG.bad", ".CONFIG.INVALID", "CONFIG.INVALID!"],
)
def test_error_code_must_be_uppercase_and_namespaced(error_code: str) -> None:
    payload = _diagnostic().model_dump(mode="python")
    payload["error_code"] = error_code
    with pytest.raises(ValidationError):
        Diagnostic.model_validate(payload)


@pytest.mark.parametrize(
    "details",
    [
        {"api_key": "forbidden"},
        {"nested": {"Auth-Token": "forbidden"}},
        {"nested": {"customer_api_key": "forbidden"}},
        {"apiKey": "forbidden"},
        {"accessToken": "forbidden"},
        {"authToken": "forbidden"},
        {"attemptToken": "forbidden"},
        {"credentials": "forbidden"},
        {"ratio": 0.5},
        {"count": 2**63},
        {"count": -(2**63) - 1},
        {"message": "x" * 2049},
        {"items": list(range(65))},
    ],
)
def test_details_reject_secrets_floats_and_bounds(
    details: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _diagnostic(details=details)


def test_details_reject_excessive_depth() -> None:
    nested: object = "leaf"
    for _ in range(10):
        nested = {"nested": nested}
    with pytest.raises(ValidationError, match="maximum depth"):
        _diagnostic(details={"root": nested})


def test_details_reject_excessive_node_count() -> None:
    groups = [{f"key{index}": index for index in range(64)} for _ in range(4)]
    with pytest.raises(ValidationError, match="too many nodes"):
        _diagnostic(details={"groups": groups})


def test_details_reject_excessive_encoded_bytes() -> None:
    with pytest.raises(ValidationError, match="encoded bytes"):
        _diagnostic(details={"payload": ["x" * 2_048 for _ in range(8)]})


@pytest.mark.parametrize(
    "category",
    [
        DiagnosticCategory.ENGINE_RUNTIME,
        DiagnosticCategory.PROTOCOL,
        DiagnosticCategory.TIMEOUT,
        DiagnosticCategory.CANCELLATION,
    ],
)
def test_command_process_and_protocol_findings_require_invocation(
    category: DiagnosticCategory,
) -> None:
    payload = _diagnostic().model_dump(mode="python")
    payload["category"] = category
    with pytest.raises(ValidationError, match="requires invocation"):
        Diagnostic.model_validate(payload)


def test_describe_invocation_does_not_invent_run_or_experiment() -> None:
    payload = _diagnostic().model_dump(mode="python")
    payload["category"] = DiagnosticCategory.ENGINE_RUNTIME
    payload["invocation_id"] = "inv_12345678-1234-4234-8234-123456789abc"
    diagnostic = Diagnostic.model_validate(payload)
    assert diagnostic.invocation_id == "inv_12345678-1234-4234-8234-123456789abc"
    dumped = diagnostic.model_dump(mode="json")
    assert "run_id" not in dumped
    assert "experiment_id" not in dumped


@pytest.mark.parametrize("causes", [(_CAUSE_ID, _CAUSE_ID), (_DIAGNOSTIC_ID,)])
def test_causal_ids_are_unique_and_not_self_referential(
    causes: tuple[str, ...],
) -> None:
    with pytest.raises(ValidationError):
        _diagnostic(causes=causes)


def test_diagnostic_rejects_unknown_fields() -> None:
    payload = _diagnostic().model_dump(mode="python")
    marker = "INPUT_MARKER_MUST_NOT_APPEAR"
    payload["customer_api_key"] = marker
    with pytest.raises(
        ValidationError,
        match="extra_forbidden",
    ) as captured:
        Diagnostic.model_validate(payload)
    assert marker not in str(captured.value)
