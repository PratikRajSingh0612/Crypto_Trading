"""Stage 9 Task 2: the normalized metric contract (plan 3.1 and 3.2 under
specification 11.3:584 -- "Numeric values are Decimal strings; units and
methodology are mandatory; missing or undefined values use an explicit status
rather than NaN")."""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Any

import pytest
from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING
from pydantic.json_schema import JsonSchemaMode

from crypto_lab.domain import MetricStatus as ExportedMetricStatus
from crypto_lab.domain import MetricValue as ExportedMetricValue
from crypto_lab.domain import MetricValueType as ExportedMetricValueType
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.metrics import MetricStatus, MetricValue, MetricValueType
from doubles.artifacts import sample_metric
from doubles.experiments import ARTIFACT_ID

_FIELDS = (
    "schema_version",
    "metric_name",
    "value",
    "value_type",
    "unit",
    "methodology_version",
    "sampling_convention",
    "comparison_level",
    "status",
    "source_artifact_id",
)
_MODES: tuple[JsonSchemaMode, ...] = ("validation", "serialization")


def _json_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "metric_name": "total-return",
        "value": "0.125",
        "value_type": "RATIO",
        "unit": "ratio",
        "methodology_version": "1.0.0",
        "sampling_convention": "close-to-close",
        "comparison_level": "LEVEL_2",
        "status": "DEFINED",
        "source_artifact_id": ARTIFACT_ID,
    }
    payload.update(overrides)
    return {key: value for key, value in payload.items() if value is not MISSING}


def test_unit_methodology_status_mandatory_no_nan() -> None:
    metric = sample_metric()
    assert metric.value == Decimal("0.125")
    assert metric.unit == "ratio"
    assert metric.methodology_version == "1.0.0"
    assert metric.status is MetricStatus.DEFINED
    assert tuple(MetricValue.model_fields) == _FIELDS
    for mandatory in (
        "unit",
        "methodology_version",
        "status",
        "sampling_convention",
        "comparison_level",
        "source_artifact_id",
        "metric_name",
        "value_type",
    ):
        assert MetricValue.model_fields[mandatory].is_required(), mandatory
        with pytest.raises(ValidationError, match="Field required"):
            sample_metric(**{mandatory: MISSING})
    assert not MetricValue.model_fields["value"].is_required()
    # No float, no NaN, no infinity: Decimal in Python, canonical text in JSON.
    with pytest.raises(ValidationError, match="must be Decimal"):
        sample_metric(value=0.125)
    with pytest.raises(ValidationError, match="finite"):
        sample_metric(value=Decimal("NaN"))
    with pytest.raises(ValidationError, match="finite"):
        sample_metric(value=Decimal("Infinity"))
    with pytest.raises(ValidationError, match="must be a string"):
        MetricValue.model_validate_json(json.dumps(_json_payload(value=0.125)))
    for text in ("NaN", "Infinity", "-Infinity", "1e3", "0.50", "+1", ".5"):
        with pytest.raises(ValidationError, match="not canonical"):
            MetricValue.model_validate_json(json.dumps(_json_payload(value=text)))
    parsed = MetricValue.model_validate_json(json.dumps(_json_payload(value="-0.5")))
    assert parsed.value == Decimal("-0.5")
    assert json.loads(parsed.model_dump_json())["value"] == "-0.5"
    # Vocabulary, exactly as plan 3.2 names it.
    assert tuple(member.value for member in MetricValueType) == (
        "DECIMAL",
        "COUNT",
        "RATIO",
        "DURATION_SECONDS",
    )
    assert tuple(member.value for member in MetricStatus) == (
        "DEFINED",
        "UNDEFINED",
        "NOT_COMPUTED",
    )
    with pytest.raises(ValidationError):
        sample_metric(value_type="PERCENT")
    with pytest.raises(ValidationError):
        sample_metric(unit="Ratio")
    with pytest.raises(ValidationError):
        sample_metric(methodology_version="1.0")
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        sample_metric(nan=True)
    assert ExportedMetricValue is MetricValue
    assert ExportedMetricStatus is MetricStatus
    assert ExportedMetricValueType is MetricValueType


def test_defined_iff_value_present() -> None:
    assert sample_metric(status=MetricStatus.DEFINED).status is MetricStatus.DEFINED
    with pytest.raises(ValidationError, match="DEFINED metric requires value"):
        sample_metric(status=MetricStatus.DEFINED, value=MISSING)
    for status in (MetricStatus.UNDEFINED, MetricStatus.NOT_COMPUTED):
        absent = sample_metric(status=status, value=MISSING)
        assert absent.status is status
        assert not isinstance(absent.value, Decimal)
        assert "value" not in json.loads(absent.model_dump_json())
        with pytest.raises(ValidationError, match="carries no value"):
            sample_metric(status=status)
    # 11.5: absent is an absent key, never ``null``.
    with pytest.raises(ValidationError):
        sample_metric(status=MetricStatus.UNDEFINED, value=None)
    with pytest.raises(ValidationError):
        MetricValue.model_validate_json(
            json.dumps(_json_payload(status="UNDEFINED", value=None))
        )
    undefined = MetricValue.model_validate_json(
        json.dumps(_json_payload(status="UNDEFINED", value=MISSING))
    )
    assert undefined.comparison_level is ComparisonLevel.LEVEL_2
    assert MetricValue.model_validate_json(undefined.model_dump_json()) == undefined
    # The published schema states the rule in both directions.
    for mode in _MODES:
        schema: dict[str, Any] = MetricValue.model_json_schema(mode=mode)
        assert schema["additionalProperties"] is False
        assert "value" not in schema["required"]
        assert schema["allOf"] == [
            {
                "if": {"properties": {"status": {"const": "DEFINED"}}},
                "then": {"required": ["value"]},
            },
            {
                "if": {
                    "properties": {"status": {"enum": ["UNDEFINED", "NOT_COMPUTED"]}}
                },
                "then": {"not": {"required": ["value"]}},
            },
        ]
        assert schema["properties"]["value"]["$ref"] == "#/$defs/CanonicalDecimal"
        assert schema["$defs"]["CanonicalDecimal"]["pattern"].startswith("^(?:0|")
        assert schema["$defs"]["CanonicalDecimal"]["type"] == "string"
    with pytest.raises(ValidationError, match="frozen"):
        sample_metric().status = MetricStatus.UNDEFINED
