"""Stage 9 Task 2: the audit event, actor and log record contracts (plan 3.1 and
3.2 under specification 11.3:586, 30.1 and 30.3).

Every refusal is exercised through the production models in strict Python mode
and the published shape is checked in JSON mode, so the schema the registry
renders is the contract the runtime enforces.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import JsonValue, ValidationError
from pydantic.experimental.missing_sentinel import MISSING
from pydantic.json_schema import JsonSchemaMode

from crypto_lab.audit.models import (
    CORE_ACTOR,
    INVOCATION_REQUIRED_ACTIONS,
    AuditAction,
    AuditActor,
    AuditEvent,
    AuditOutcome,
    LogRecord,
    LogSeverity,
    audit_details_hash,
)
from crypto_lab.audit.redaction import REDACTED
from crypto_lab.domain.hashing import HashingProfile, profile_hash
from doubles.artifacts import (
    ADAPTER_ACTOR,
    AUDIT_EVENT_ID,
    CORRELATION_ID,
    LOCAL_USER_ACTOR,
    SAMPLE_DETAILS,
    sample_audit_event,
    sample_log_record,
)
from doubles.experiments import INVOCATION_ID

#: Plan 3.2: the closed set of 25 actions, in the plan's order.
_PLAN_ACTIONS = (
    "ARTIFACT_CANDIDATE_REGISTERED",
    "ARTIFACT_VALIDATED",
    "ARTIFACT_VALIDATION_FAILED",
    "ARTIFACT_OWNER_PURPOSE_SELECTED",
    "FINALIZATION_LEASE_ACQUIRED",
    "FINALIZATION_LEASE_REFUSED",
    "FINALIZATION_PREPARED",
    "FINALIZATION_MOVED",
    "FINALIZATION_REGISTERED",
    "FINALIZATION_REPLAYED",
    "FINALIZATION_ABANDONED",
    "FINALIZATION_TIMED_OUT",
    "ARTIFACT_QUARANTINED",
    "ARTIFACT_CORRUPT",
    "ARTIFACT_LEAKAGE_DETECTED",
    "RUN_SUCCEEDED",
    "RUN_FAILED",
    "RUN_MANIFEST_REGISTERED",
    "STDERR_TRUNCATED",
    "STDERR_EVIDENCE_LINKED",
    "RECONCILIATION_FINALIZATION_RESUMED",
    "RECONCILIATION_CANDIDATE_QUARANTINED",
    "RECONCILIATION_ORPHAN_QUARANTINED",
    "RETENTION_DELETED",
    "QUARANTINE_OVERDUE",
)
#: 11.3:586 by name: the actions tied to one command invocation -- the run's
#: terminal and manifest writes driven by the run command's exit facts, the two
#: stderr facts of that command, and the RESULT finalization timeout (EVIDENCE
#: journals carry no deadline, reading 13).
_COMMAND_ACTIONS = frozenset(
    {
        "RUN_SUCCEEDED",
        "RUN_FAILED",
        "RUN_MANIFEST_REGISTERED",
        "STDERR_TRUNCATED",
        "STDERR_EVIDENCE_LINKED",
        "FINALIZATION_TIMED_OUT",
    }
)
_TOKEN_SHAPED = "A" * 32
_MODES: tuple[JsonSchemaMode, ...] = ("validation", "serialization")
_AUDIT_EVENT_FIELDS = (
    "schema_version",
    "audit_event_id",
    "action",
    "actor",
    "outcome",
    "experiment_id",
    "run_id",
    "invocation_id",
    "artifact_id",
    "timestamp_utc",
    "correlation_id",
    "details_hash",
    "details",
)
_LOG_RECORD_FIELDS = (
    "schema_version",
    "timestamp_utc",
    "severity",
    "component",
    "event_code",
    "correlation_id",
    "experiment_id",
    "run_id",
    "invocation_id",
    "adapter",
    "engine",
    "message",
    "details",
)


def test_action_set_is_exactly_twenty_five() -> None:
    members = tuple(AuditAction)
    assert len(members) == 25
    assert tuple(member.name for member in members) == _PLAN_ACTIONS
    assert all(member.value == member.name for member in members)
    assert tuple(member.value for member in AuditOutcome) == (
        "SUCCEEDED",
        "REFUSED",
        "FAILED",
    )
    assert tuple(member.value for member in LogSeverity) == (
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
        "CRITICAL",
    )


def test_unknown_fields_rejected() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        sample_audit_event(sequence=1)
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        sample_log_record(ordering=1)
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AuditActor.model_validate({"kind": "CORE", "engine": "engine.alpha"})
    # 11.5: an absent field is an absent key; ``None`` is not ``MISSING``.
    with pytest.raises(ValidationError):
        sample_audit_event(artifact_id=None)
    with pytest.raises(ValidationError):
        sample_log_record(engine=None)
    # Strict mode: a string outcome is accepted in JSON, a coerced value is not.
    with pytest.raises(ValidationError):
        sample_audit_event(outcome=1)


@pytest.mark.parametrize("action", list(AuditAction))
def test_invocation_required_for_command_actions(action: AuditAction) -> None:
    """11.3:586 by name: the six command-tied actions require ``invocation_id``
    and the other nineteen accept its absence; every action accepts its presence."""
    assert {member.name for member in INVOCATION_REQUIRED_ACTIONS} == _COMMAND_ACTIONS
    with_invocation = sample_audit_event(action)
    assert with_invocation.invocation_id == INVOCATION_ID
    if action in INVOCATION_REQUIRED_ACTIONS:
        with pytest.raises(ValidationError, match="requires invocation_id"):
            sample_audit_event(action, invocation_id=MISSING)
    else:
        without = sample_audit_event(action, invocation_id=MISSING)
        assert not isinstance(without.invocation_id, str)
        assert "invocation_id" not in json.loads(without.model_dump_json())


def test_details_hash_recomputed() -> None:
    event = sample_audit_event()
    payload: dict[str, JsonValue] = {"stage": "HASH", "observed": 2}
    assert event.details_hash == profile_hash(
        HashingProfile.AUDIT_EVENT_DETAILS_V1, payload
    )
    assert HashingProfile.AUDIT_EVENT_DETAILS_V1.value == "audit-event-details/v1"
    with pytest.raises(ValidationError, match="details_hash"):
        sample_audit_event(details_hash="0" * 64)
    with pytest.raises(ValidationError, match="details_hash"):
        sample_audit_event(details={"stage": "MOVE"}, details_hash=event.details_hash)
    # Canonical JSON orders keys, so insertion order is not hash material.
    assert audit_details_hash({"observed": 2, "stage": "HASH"}) == event.details_hash
    assert audit_details_hash({"stage": "HASH", "observed": 3}) != event.details_hash
    # The profile name is part of the hash domain.
    assert profile_hash(HashingProfile.ARTIFACT_OWNER_V1, payload) != event.details_hash
    empty = sample_audit_event(details={})
    assert empty.details_hash == audit_details_hash({})


def test_details_with_token_shape_rejected() -> None:
    """The redaction fixed point: a token-shaped value, at any depth, and a
    denylisted key are refused by the model rather than silently redacted."""
    with pytest.raises(ValidationError, match="redaction fixed point"):
        sample_audit_event(details={"token_like": _TOKEN_SHAPED})
    with pytest.raises(ValidationError, match="redaction fixed point"):
        sample_audit_event(details={"nested": [{"deep": f"saw {_TOKEN_SHAPED} here"}]})
    with pytest.raises(ValidationError, match="secret-like"):
        sample_audit_event(details={"api_key": "short"})
    with pytest.raises(ValidationError, match="secret-like"):
        sample_audit_event(details={"outer": {"credentials": 1}})
    with pytest.raises(ValidationError, match="redaction fixed point"):
        sample_log_record(details={"token_like": _TOKEN_SHAPED})
    with pytest.raises(ValidationError, match="redaction fixed point"):
        sample_log_record(message=f"saw {_TOKEN_SHAPED}")
    # The redacted form is its own fixed point and is accepted.
    accepted = sample_audit_event(details={"token_like": REDACTED})
    assert accepted.details == {"token_like": REDACTED}
    assert sample_log_record(message=REDACTED).message == REDACTED
    # The Stage 3 detail ceilings bound both records.
    with pytest.raises(ValidationError, match="at most 2048"):
        sample_audit_event(details={"text": "a" * 2049})
    with pytest.raises(ValidationError, match="at most 64"):
        sample_log_record(details={f"k{index}": index for index in range(65)})
    with pytest.raises(ValidationError, match="at most 1024"):
        sample_log_record(message="m" * 1025)
    with pytest.raises(ValidationError, match="too many nodes"):
        sample_audit_event(details={f"k{index}": [0] * 4 for index in range(60)})


def test_actor_adapter_requires_both_fields() -> None:
    assert ADAPTER_ACTOR.adapter_name == "adapter.alpha"
    assert ADAPTER_ACTOR.adapter_version == "1.0.0"
    assert CORE_ACTOR.kind == "CORE"
    assert not isinstance(CORE_ACTOR.adapter_name, str)
    assert LOCAL_USER_ACTOR.kind == "LOCAL_USER"
    for partial in (
        {"kind": "ADAPTER"},
        {"kind": "ADAPTER", "adapter_name": "adapter.alpha"},
        {"kind": "ADAPTER", "adapter_version": "1.0.0"},
    ):
        with pytest.raises(ValidationError, match="ADAPTER actor requires"):
            AuditActor.model_validate(partial)
    for kind in ("CORE", "LOCAL_USER"):
        with pytest.raises(ValidationError, match="names no adapter"):
            AuditActor.model_validate(
                {
                    "kind": kind,
                    "adapter_name": "adapter.alpha",
                    "adapter_version": "1.0.0",
                }
            )
        with pytest.raises(ValidationError, match="names no adapter"):
            AuditActor.model_validate({"kind": kind, "adapter_name": "adapter.alpha"})
    with pytest.raises(ValidationError):
        AuditActor.model_validate({"kind": "SYSTEM"})
    with pytest.raises(ValidationError):
        AuditActor.model_validate(
            {"kind": "ADAPTER", "adapter_name": "Adapter", "adapter_version": "1.0.0"}
        )
    with pytest.raises(ValidationError):
        AuditActor.model_validate(
            {
                "kind": "ADAPTER",
                "adapter_name": "adapter.alpha",
                "adapter_version": "1",
            }
        )
    event = sample_audit_event(actor=ADAPTER_ACTOR)
    assert event.actor == ADAPTER_ACTOR
    assert json.loads(event.model_dump_json())["actor"] == {
        "kind": "ADAPTER",
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
    }


def test_audit_event_has_no_ordering_field() -> None:
    """Reading 9 and 30.2: ordering is the audit identifier sequence the sink
    assigns, so the model carries no ordering field; the field tables are exact."""
    assert tuple(AuditEvent.model_fields) == _AUDIT_EVENT_FIELDS
    assert not {"sequence", "audit_sequence", "ordinal", "position"} & set(
        AuditEvent.model_fields
    )
    assert tuple(LogRecord.model_fields) == _LOG_RECORD_FIELDS
    assert tuple(AuditActor.model_fields) == ("kind", "adapter_name", "adapter_version")
    for name in ("experiment_id", "run_id", "invocation_id", "artifact_id"):
        assert not AuditEvent.model_fields[name].is_required(), name
    for name in ("experiment_id", "run_id", "invocation_id", "adapter", "engine"):
        assert not LogRecord.model_fields[name].is_required(), name
    required = [
        name for name, field in AuditEvent.model_fields.items() if field.is_required()
    ]
    assert required == [
        "schema_version",
        "audit_event_id",
        "action",
        "actor",
        "outcome",
        "timestamp_utc",
        "correlation_id",
        "details_hash",
        "details",
    ]


def test_records_round_trip_through_json_and_omit_missing() -> None:
    event = sample_audit_event(artifact_id=MISSING, run_id=MISSING)
    document = json.loads(event.model_dump_json())
    assert "artifact_id" not in document
    assert "run_id" not in document
    assert document["timestamp_utc"] == "2026-09-07T12:00:00Z"
    assert document["audit_event_id"] == AUDIT_EVENT_ID
    assert document["correlation_id"] == CORRELATION_ID
    assert document["details"] == SAMPLE_DETAILS
    assert AuditEvent.model_validate_json(event.model_dump_json()) == event
    record = sample_log_record(adapter=MISSING, engine=MISSING, run_id=MISSING)
    rendered = json.loads(record.model_dump_json())
    assert {"adapter", "engine", "run_id"}.isdisjoint(rendered)
    assert rendered["severity"] == "INFO"
    assert LogRecord.model_validate_json(record.model_dump_json()) == record
    with pytest.raises(ValidationError, match="frozen"):
        event.details = {}
    with pytest.raises(ValidationError):
        LogRecord.model_validate_json(json.dumps({**rendered, "severity": "TRACE"}))
    with pytest.raises(ValidationError):
        LogRecord.model_validate_json(json.dumps({**rendered, "event_code": "lower"}))


def test_audit_event_schema_publishes_the_invocation_rule() -> None:
    """The Diagnostic precedent: the action-dependent requirement is published
    as ``if``/``then`` over the emitted enum, and every timestamp uses the
    forward calendar-exact view."""
    for model in (AuditEvent, LogRecord):
        for mode in _MODES:
            schema: dict[str, Any] = model.model_json_schema(mode=mode)
            assert schema["additionalProperties"] is False
            assert "CalendarValidUtcDateTime" in schema["$defs"], model.__name__
            assert "UtcDateTime" not in schema["$defs"], model.__name__
    audit_schema = AuditEvent.model_json_schema(mode="serialization")
    assert audit_schema["allOf"] == [
        {
            "if": {
                "properties": {"action": {"enum": sorted(_COMMAND_ACTIONS)}},
                "required": ["action"],
            },
            "then": {"required": ["invocation_id"]},
        }
    ]
    assert audit_schema["properties"]["details"] == {"$ref": "#/$defs/BoundedDetails"}
    bounded = audit_schema["$defs"]["BoundedDetails"]
    assert bounded["type"] == "object"
    assert bounded["maxProperties"] == 64
    assert bounded["additionalProperties"] == {"$ref": "#/$defs/DiagnosticDetailValue"}
    assert bounded["propertyNames"] == {"$ref": "#/$defs/DiagnosticDetailKey"}
    assert audit_schema["$defs"]["AuditAction"]["enum"] == list(_PLAN_ACTIONS)
    assert "allOf" not in LogRecord.model_json_schema(mode="serialization")
