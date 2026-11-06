"""Deterministic builders and doubles for the Stage 9 audit, log and metric
contracts (Stage 9 plan section 7.1; Task 2 creates this module with the
builders it needs, later tasks extend it).

Test-resident like ``doubles.experiments``: nothing under ``crypto_lab``
imports this module. ``SequentialAuditIds`` is the deterministic
``AuditEventIds`` double -- every identifier derives from a seed and a counter
through the existing ``_uuid4_shaped`` reshaping, so identical draw order yields
identical identifiers and no random source is consulted. The ``sample_*``
builders return production records validated in Python mode over the shared
doubles identities; an override whose value is ``MISSING`` removes the key, so a
test can build the record without that field.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Final

from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.audit.models import (
    CORE_ACTOR,
    LOCAL_USER_ACTOR,
    AuditAction,
    AuditActor,
    AuditEvent,
    AuditOutcome,
    LogRecord,
    LogSeverity,
    audit_details_hash,
)
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.hashing import _uuid4_shaped, sha256_bytes
from crypto_lab.domain.metrics import MetricStatus, MetricValue, MetricValueType
from doubles.experiments import (
    ARTIFACT_ID,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    RUN_ID,
    UUID_A,
)

AUDIT_EVENT_ID: Final = f"audit_{UUID_A}"
CORRELATION_ID: Final = "stage9.task2"
ADAPTER_ACTOR: Final = AuditActor(
    kind="ADAPTER", adapter_name="adapter.alpha", adapter_version="1.0.0"
)
SAMPLE_DETAILS: Final[dict[str, Any]] = {"stage": "HASH", "observed": 2}


class SequentialAuditIds:
    """Derives every ``audit_`` identifier from a fixed seed and a counter."""

    def __init__(self, prefix_seed: str = "task2") -> None:
        self._prefix_seed = prefix_seed
        self._issued: list[str] = []

    def new_audit_event_id(self) -> str:
        ordinal = len(self._issued) + 1
        digest = sha256_bytes(f"{self._prefix_seed}\x00audit\x00{ordinal}".encode())
        identifier = f"audit_{_uuid4_shaped(digest)}"
        self._issued.append(identifier)
        return identifier

    @property
    def issued(self) -> tuple[str, ...]:
        return tuple(self._issued)


def _without_missing(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if value is not MISSING}


def sample_audit_event(
    action: AuditAction = AuditAction.ARTIFACT_VALIDATED, **overrides: Any
) -> AuditEvent:
    """A ``CORE`` ``SUCCEEDED`` event carrying every correlation identifier."""
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "audit_event_id": AUDIT_EVENT_ID,
        "action": action,
        "actor": CORE_ACTOR,
        "outcome": AuditOutcome.SUCCEEDED,
        "experiment_id": EXPERIMENT_ID,
        "run_id": RUN_ID,
        "invocation_id": INVOCATION_ID,
        "artifact_id": ARTIFACT_ID,
        "timestamp_utc": INSTANT,
        "correlation_id": CORRELATION_ID,
        "details": dict(SAMPLE_DETAILS),
    }
    payload.update(overrides)
    payload = _without_missing(payload)
    if "details_hash" not in payload:
        payload["details_hash"] = audit_details_hash(payload["details"])
    return AuditEvent.model_validate(payload)


def sample_log_record(**overrides: Any) -> LogRecord:
    """An ``INFO`` record of the artifact component with every identifier."""
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "timestamp_utc": INSTANT,
        "severity": LogSeverity.INFO,
        "component": "core.artifacts",
        "event_code": "ARTIFACT.VALIDATED",
        "correlation_id": CORRELATION_ID,
        "experiment_id": EXPERIMENT_ID,
        "run_id": RUN_ID,
        "invocation_id": INVOCATION_ID,
        "adapter": "adapter.alpha",
        "engine": "engine.alpha",
        "message": "candidate validated",
        "details": dict(SAMPLE_DETAILS),
    }
    payload.update(overrides)
    return LogRecord.model_validate(_without_missing(payload))


def sample_metric(**overrides: Any) -> MetricValue:
    """A ``DEFINED`` ratio metric with a canonical Decimal value."""
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "metric_name": "total-return",
        "value": Decimal("0.125"),
        "value_type": MetricValueType.RATIO,
        "unit": "ratio",
        "methodology_version": "1.0.0",
        "sampling_convention": "close-to-close",
        "comparison_level": ComparisonLevel.LEVEL_2,
        "status": MetricStatus.DEFINED,
        "source_artifact_id": ARTIFACT_ID,
    }
    payload.update(overrides)
    return MetricValue.model_validate(_without_missing(payload))


__all__ = (
    "ADAPTER_ACTOR",
    "AUDIT_EVENT_ID",
    "CORRELATION_ID",
    "LOCAL_USER_ACTOR",
    "SAMPLE_DETAILS",
    "SequentialAuditIds",
    "sample_audit_event",
    "sample_log_record",
    "sample_metric",
)
