"""The normalized result metric contract.

Stage 9 plan sections 3.1 and 3.2 under specification 11.3:584: a named
normalized result metric whose numeric value is a canonical ``Decimal`` (a
string in JSON, a ``Decimal`` in Python, never a float, never ``NaN``), whose
unit, methodology version, sampling convention and comparison level are
mandatory, and whose absence is an explicit ``status`` rather than a sentinel
number: ``DEFINED`` exactly when ``value`` is present, ``UNDEFINED`` or
``NOT_COMPUTED`` exactly when it is absent. Every metric names the finalized
artifact it was read from. The module imports ``domain`` alone.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, Literal, Self

from pydantic import ConfigDict, model_validator
from pydantic.experimental.missing_sentinel import MISSING
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.financial import CanonicalDecimal
from crypto_lab.domain.identifiers import ArtifactId, NormalizedIdentifier
from crypto_lab.domain.versioning import SemanticVersion


class MetricValueType(StrEnum):
    DECIMAL = "DECIMAL"
    COUNT = "COUNT"
    RATIO = "RATIO"
    DURATION_SECONDS = "DURATION_SECONDS"


class MetricStatus(StrEnum):
    DEFINED = "DEFINED"
    UNDEFINED = "UNDEFINED"
    NOT_COMPUTED = "NOT_COMPUTED"


def _is_missing(value: object) -> bool:
    return value is MISSING


def _metric_schema_extra(schema: JsonSchemaValue) -> None:
    schema["allOf"] = [
        {
            "if": {"properties": {"status": {"const": MetricStatus.DEFINED.value}}},
            "then": {"required": ["value"]},
        },
        {
            "if": {
                "properties": {
                    "status": {
                        "enum": [
                            MetricStatus.UNDEFINED.value,
                            MetricStatus.NOT_COMPUTED.value,
                        ]
                    }
                }
            },
            "then": {"not": {"required": ["value"]}},
        },
    ]


class MetricValue(CanonicalModel):
    """Specification 11.3: a named normalized result metric.

    ``value`` is present exactly when ``status`` is ``DEFINED``; the published
    schema states the rule in both directions.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_metric_schema_extra
    )

    schema_version: Literal["1.0.0"]
    metric_name: NormalizedIdentifier
    value: CanonicalDecimal | MISSING = MISSING  # type: ignore[valid-type]
    value_type: MetricValueType
    unit: NormalizedIdentifier
    methodology_version: SemanticVersion
    sampling_convention: NormalizedIdentifier
    comparison_level: ComparisonLevel
    status: MetricStatus
    source_artifact_id: ArtifactId

    @model_validator(mode="after")
    def validate_status_governs_value(self) -> Self:
        present = not _is_missing(self.value)
        if self.status is MetricStatus.DEFINED and not present:
            raise ValueError("a DEFINED metric requires value")
        if self.status is not MetricStatus.DEFINED and present:
            raise ValueError(f"a {self.status.value} metric carries no value")
        return self


__all__ = (
    "MetricStatus",
    "MetricValue",
    "MetricValueType",
)
