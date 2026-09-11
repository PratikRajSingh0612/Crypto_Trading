"""Stage 6 Task 4: protocol events and the staged line parser (plan sections 3.9,
4, 7.1-7.4; specification 10.2, 11.3, 11.5, 14.4, 14.7, 21.2.1).

The temporary wire envelope, the six strict payloads, the sanitized ``RunEvent`` and
its ``RUN_EVENT_CONTENT_V1`` identity, the discriminated line outcome, the
acceptance context, the incremental framer and ``parse_protocol_line`` -- every
framing rule with a positive and a negative line, the version check, every identity
and sequence rule of plan 7.3, redaction before strict validation, the path-located
classification, and the parser never raising on adapter-controlled bytes.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Final, Literal, Never, get_args

import pytest
from jsonschema import Draft202012Validator
from pydantic import TypeAdapter, ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab import adapters as adapters_package
from crypto_lab.adapters import events
from crypto_lab.adapters.diagnostics import (
    ARTIFACT_PATH_BOUNDARY_VIOLATION,
    PROTOCOL_EVENT_TOO_LARGE,
    PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
    PROTOCOL_MALFORMED_JSONL,
    PROTOCOL_STDOUT_CONTAMINATION,
    PROTOCOL_UNSUPPORTED_VERSION,
)
from crypto_lab.adapters.events import (
    AdapterDiagnostic,
    ArtifactDeclarationRecord,
    ArtifactProducedPayload,
    DiagnosticPayload,
    EventAcceptanceContext,
    EventAccepted,
    EventRejected,
    EventReplayed,
    FinalResultPayload,
    HeartbeatPayload,
    InvocationEventLedger,
    LineOutcome,
    MediaType,
    ProgressPayload,
    ProtocolEventEnvelope,
    ProtocolEventSummary,
    ProtocolWarning,
    ResourceObservation,
    RunEvent,
    WarningPayload,
    _EventHeader,
    _Rejecter,
    frame_protocol_lines,
    parse_protocol_line,
    run_event_content_hash,
)
from crypto_lab.adapters.limits import (
    MAX_CAUSAL_EVENT_IDS,
    MAX_COUNTER,
    MAX_DECLARED_SIZE_BYTES,
    MAX_EVENT_LINE_BYTES,
    MAX_SEQUENCE,
)
from crypto_lab.adapters.sanitization import (
    REDACTION_PLACEHOLDER,
    BoundedStderrCapture,
    ContaminationSample,
    StderrCapture,
    contamination_sample,
)
from crypto_lab.adapters.vocabulary import ProtocolEventType
from crypto_lab.domain.base import SCHEMA_VERSION
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import DiagnosticCategory, DiagnosticSeverity
from crypto_lab.domain.hashing import (
    HashingProfile,
    _uuid4_shaped,
    attempt_token_hash,
    profile_hash,
    sha256_bytes,
)
from crypto_lab.domain.lifecycle import CommandInvocationState, CommandKind
from doubles.experiments import (
    ATTEMPT_TOKEN,
    INVOCATION_ID,
    OTHER_INVOCATION_ID,
    OTHER_RUN_ID,
    RUN_ID,
    CountingClock,
    FixedClock,
    sample_invocation,
)

_MODES: Final[tuple[Literal["python", "json"], ...]] = ("python", "json")
_RECEIVED: Final = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)
_STAMP: Final = "2026-09-11T10:00:01Z"
_HASH: Final = "a" * 64
_OTHER_HASH: Final = "b" * 64
#: A token that is also a valid lowercase identifier and a valid path segment (plan
#: 7.4: "a token drawn from the letter-leading subset of the AttemptToken grammar").
_IDENTIFIER_TOKEN: Final = "a" * 32
_WRONG_TOKEN: Final = "B" * 32
_HEARTBEAT: Final[dict[str, Any]] = {"activity_counter": 1, "phase": "warmup"}
_PROGRESS: Final[dict[str, Any]] = {
    "phase": "backtest",
    "completed_units": 5,
    "total_units": 10,
    "percentage": "50",
}
_WARNING: Final[dict[str, Any]] = {
    "warning": {
        "warning_code": "ADAPTER.APPROXIMATED_FILLS",
        "message": "fills approximated at bar close",
        "impact": "Level 3 comparison prevented.",
        "prevented_comparison_levels": ["LEVEL_3"],
    }
}
_DIAGNOSTIC: Final[dict[str, Any]] = {
    "diagnostic": {
        "error_code": "ENGINE.DATA_GAP",
        "category": "ENGINE_RUNTIME",
        "severity": "WARNING",
        "message": "one bar missing",
        "retriable": True,
        "details": {"bars": 1},
        "causal_event_ids": [],
    }
}
_ARTIFACT: Final[dict[str, Any]] = {
    "relative_path": "results/native.bin",
    "artifact_kind": "engine.native",
    "media_type": "application/octet-stream",
    "declared_size_bytes": 12,
    "declared_sha256": _HASH,
}
_FINAL: Final[dict[str, Any]] = {
    "manifest_relative_path": "adapter-result-manifest.json",
    "source_adapter_result_manifest_hash": _OTHER_HASH,
    "semantic_status": "SUCCEEDED",
}
_PAYLOADS: Final[dict[str, dict[str, Any]]] = {
    "HEARTBEAT": _HEARTBEAT,
    "PROGRESS": _PROGRESS,
    "WARNING": _WARNING,
    "DIAGNOSTIC": _DIAGNOSTIC,
    "ARTIFACT_PRODUCED": _ARTIFACT,
    "FINAL_RESULT": _FINAL,
}
_PAYLOAD_CLASSES: Final[dict[str, type[Any]]] = {
    "HEARTBEAT": HeartbeatPayload,
    "PROGRESS": ProgressPayload,
    "WARNING": WarningPayload,
    "DIAGNOSTIC": DiagnosticPayload,
    "ARTIFACT_PRODUCED": ArtifactProducedPayload,
    "FINAL_RESULT": FinalResultPayload,
}
#: Plan section 14 Task 4: the Task 4 public surface of ``crypto_lab.adapters``.
_TASK4_EXPORTS: Final = frozenset(
    {
        "REDACTION_PLACEHOLDER",
        "AdapterDiagnostic",
        "ArtifactDeclarationRecord",
        "ArtifactProducedPayload",
        "BoundedStderrCapture",
        "ContaminationSample",
        "DiagnosticPayload",
        "EventAccepted",
        "EventAcceptanceContext",
        "EventRejected",
        "EventReplayed",
        "FinalResultPayload",
        "HeartbeatPayload",
        "InvocationEventLedger",
        "LineOutcome",
        "MediaType",
        "ProgressPayload",
        "ProtocolEventEnvelope",
        "ProtocolEventSummary",
        "ProtocolWarning",
        "ResourceObservation",
        "RunEvent",
        "StderrCapture",
        "WarningPayload",
        "contamination_sample",
        "frame_protocol_lines",
        "parse_protocol_line",
        "redact_attempt_token",
        "redact_payload",
        "run_event_content_hash",
        "token_present",
    }
)
_PURE_ROOTS: Final = frozenset(
    {
        "__future__",
        "collections",
        "dataclasses",
        "datetime",
        "json",
        "typing",
        "pydantic",
        "crypto_lab",
    }
)
_STAGE4_BARE_NAMES: Final = frozenset(
    {"buffer", "context", "note", "problem", "compose", "Loader", "get_snippet"}
)
_ENVELOPE_FIELDS: Final = (
    "schema_version",
    "protocol_version",
    "event_id",
    "invocation_id",
    "run_id",
    "attempt_token",
    "sequence",
    "event_type",
    "timestamp_utc",
    "payload",
)
_RUN_EVENT_FIELDS: Final = (
    "schema_version",
    "protocol_version",
    "event_id",
    "invocation_id",
    "run_id",
    "attempt_token_hash",
    "sequence",
    "event_type",
    "timestamp_utc",
    "payload",
    "received_at_utc",
    "wire_event_hash",
    "content_hash",
)
_HEADER_FIELDS: Final = (
    "protocol_version",
    "schema_version",
    "invocation_id",
    "run_id",
    "sequence",
    "event_type",
    "attempt_token_hash",
)
_PATH_FIELDS: Final = frozenset({"relative_path", "manifest_relative_path"})
_CODES: Final = frozenset(
    {
        PROTOCOL_STDOUT_CONTAMINATION,
        PROTOCOL_MALFORMED_JSONL,
        PROTOCOL_EVENT_TOO_LARGE,
        PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
        PROTOCOL_UNSUPPORTED_VERSION,
        ARTIFACT_PATH_BOUNDARY_VIOLATION,
    }
)
#: Recorded once from the stdlib formula in ``test_the_content_hash_golden_...``.
_CONTENT_GOLDEN: Final = (
    "b7c1412ad59fc8faa5732b69d024397b2099d48f2d5eca20280de114166b6b33"
)


def _missing(value: object) -> bool:
    return value is MISSING


def _forbidden(*_args: object, **_kwargs: object) -> Never:
    raise AssertionError("Task 4 performed runtime work")


def _event_id(seed: object) -> str:
    return f"evt_{_uuid4_shaped(sha256_bytes(str(seed).encode('utf-8')))}"


def _document(**updates: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": "1.0.0",
        "protocol_version": "1.0.0",
        "event_id": _event_id(f"{INVOCATION_ID}:1"),
        "invocation_id": INVOCATION_ID,
        "run_id": RUN_ID,
        "attempt_token": ATTEMPT_TOKEN,
        "sequence": 1,
        "event_type": "HEARTBEAT",
        "timestamp_utc": _STAMP,
        "payload": _HEARTBEAT,
    }
    document.update(updates)
    return document


def _typed(event_type: str, sequence: int = 1, **updates: Any) -> dict[str, Any]:
    payload = updates.pop("payload", _PAYLOADS[event_type])
    return _document(
        event_type=event_type,
        payload=payload,
        sequence=sequence,
        event_id=_event_id(f"{INVOCATION_ID}:{sequence}"),
        **updates,
    )


def _encode(document: dict[str, Any], terminator: bytes = b"\n") -> bytes:
    # ``ensure_ascii`` so a lone-surrogate fixture is a JSON escape, never a byte.
    text = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return text.encode("utf-8") + terminator


def _line(**updates: Any) -> bytes:
    return _encode(_document(**updates))


def _acceptance(
    *,
    kind: CommandKind = CommandKind.RUN,
    ledger: InvocationEventLedger | None = None,
    clock: FixedClock | None = None,
    max_event_bytes: int = MAX_EVENT_LINE_BYTES,
    token: str = ATTEMPT_TOKEN,
) -> EventAcceptanceContext:
    return EventAcceptanceContext(
        invocation=sample_invocation(CommandInvocationState.RUNNING, kind=kind),
        attempt_token_hash=attempt_token_hash(token),
        max_event_bytes=max_event_bytes,
        ledger=InvocationEventLedger() if ledger is None else ledger,
        clock=FixedClock(_RECEIVED) if clock is None else clock,
    )


def _parse(line: bytes, **acceptance: Any) -> LineOutcome:
    return parse_protocol_line(line, acceptance=_acceptance(**acceptance))


def _feed(
    lines: list[bytes], **acceptance: Any
) -> tuple[list[LineOutcome], InvocationEventLedger]:
    ledger = InvocationEventLedger()
    outcomes: list[LineOutcome] = []
    for line in lines:
        outcome = _parse(line, ledger=ledger, **acceptance)
        outcomes.append(outcome)
        ledger = ledger.accept(outcome)
    return outcomes, ledger


def _code(outcome: LineOutcome) -> str:
    assert isinstance(outcome, EventRejected), outcome
    return outcome.diagnostic.error_code


def _accepted(outcome: LineOutcome) -> RunEvent:
    assert isinstance(outcome, EventAccepted), outcome
    return outcome.event


def _run_event(**changes: Any) -> RunEvent:
    """The conformant heartbeat's RunEvent with ``changes`` and its hash recomputed."""
    base = _accepted(_parse(_line()))
    draft = RunEvent.model_construct(**{**dict(base), **changes})
    payload = draft.model_dump(mode="python")
    payload["content_hash"] = run_event_content_hash(draft)
    return RunEvent.model_validate(payload)


def _stdlib_digest(document: object) -> str:
    return hashlib.sha256(
        json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


# --- Inventory, field order and purity ----------------------------------------------


def test_the_package_exports_the_task_four_surface_sorted() -> None:
    exported = adapters_package.__all__
    assert _TASK4_EXPORTS <= set(exported), sorted(_TASK4_EXPORTS - set(exported))
    assert len(set(exported)) == len(exported)
    constants = [name for name in exported if name.isupper()]
    classes = [name for name in exported if not name.isupper() and name[0].isupper()]
    functions = [name for name in exported if name[0].islower()]
    assert list(exported) == [*constants, *classes, *functions]
    for group in (constants, classes, functions):
        assert group == sorted(group)
    assert "_EventHeader" not in exported
    assert "AdapterErrorCode" not in exported


@pytest.mark.parametrize(
    ("model", "expected", "optional"),
    [
        (
            AdapterDiagnostic,
            (
                "error_code",
                "category",
                "severity",
                "message",
                "retriable",
                "details",
                "causal_event_ids",
            ),
            (),
        ),
        (
            ProtocolWarning,
            ("warning_code", "message", "impact", "prevented_comparison_levels"),
            (),
        ),
        (
            ResourceObservation,
            ("resident_memory_bytes", "cpu_seconds"),
            ("resident_memory_bytes", "cpu_seconds"),
        ),
        (
            HeartbeatPayload,
            ("activity_counter", "phase", "resource_observation"),
            ("resource_observation",),
        ),
        (
            ProgressPayload,
            ("phase", "completed_units", "total_units", "percentage"),
            ("total_units", "percentage"),
        ),
        (WarningPayload, ("warning",), ()),
        (DiagnosticPayload, ("diagnostic",), ()),
        (
            ArtifactProducedPayload,
            (
                "relative_path",
                "artifact_kind",
                "media_type",
                "declared_size_bytes",
                "declared_sha256",
            ),
            (),
        ),
        (
            FinalResultPayload,
            (
                "manifest_relative_path",
                "source_adapter_result_manifest_hash",
                "semantic_status",
            ),
            (),
        ),
        (ProtocolEventEnvelope, _ENVELOPE_FIELDS, ()),
        (RunEvent, _RUN_EVENT_FIELDS, ()),
        (EventAccepted, ("outcome", "event", "redactions"), ()),
        (EventReplayed, ("outcome", "event"), ()),
        (EventRejected, ("outcome", "diagnostic", "sample"), ()),
        (ArtifactDeclarationRecord, ("event_id", "payload"), ()),
        (
            ProtocolEventSummary,
            (
                "accepted_count",
                "last_sequence",
                "artifact_declarations",
                "warnings",
                "final_result",
                "adapter_diagnostics",
                "redactions",
            ),
            ("final_result",),
        ),
        (_EventHeader, _HEADER_FIELDS, _HEADER_FIELDS),
    ],
    ids=lambda value: value.__name__ if isinstance(value, type) else "fields",
)
def test_each_model_declares_exactly_the_plan_fields_in_order(
    model: type[Any], expected: tuple[str, ...], optional: tuple[str, ...]
) -> None:
    assert tuple(model.model_fields) == expected
    for name, field in model.model_fields.items():
        assert field.is_required() is (name not in optional), name


def test_version_literals_and_envelope_conventions_are_exact() -> None:
    for model in (ProtocolEventEnvelope, RunEvent):
        fields = model.model_fields
        assert get_args(fields["schema_version"].annotation) == (SCHEMA_VERSION,)
        assert get_args(fields["protocol_version"].annotation) == (SCHEMA_VERSION,)
    nested: list[type[Any]] = [
        *_PAYLOAD_CLASSES.values(),
        AdapterDiagnostic,
        ProtocolWarning,
        ResourceObservation,
        EventAccepted,
        EventReplayed,
        EventRejected,
        ArtifactDeclarationRecord,
        ProtocolEventSummary,
        ContaminationSample,
        StderrCapture,
    ]
    for record in nested:
        assert "schema_version" not in record.model_fields, record.__name__
        assert "protocol_version" not in record.model_fields, record.__name__
    assert get_args(EventAccepted.model_fields["outcome"].annotation) == ("ACCEPTED",)
    assert get_args(EventReplayed.model_fields["outcome"].annotation) == ("REPLAYED",)
    assert get_args(EventRejected.model_fields["outcome"].annotation) == ("REJECTED",)


def test_only_the_wire_envelope_carries_the_raw_token() -> None:
    """Section 13: the four-class allowlist; among the Task 4 models exactly one."""
    token_free: list[type[Any]] = [
        *_PAYLOAD_CLASSES.values(),
        AdapterDiagnostic,
        ProtocolWarning,
        ResourceObservation,
        RunEvent,
        EventAccepted,
        EventReplayed,
        EventRejected,
        ArtifactDeclarationRecord,
        ProtocolEventSummary,
        _EventHeader,
        ContaminationSample,
        StderrCapture,
    ]
    for model in token_free:
        assert "attempt_token" not in model.model_fields, model.__name__
        for field in model.model_fields.values():
            assert "AttemptToken" not in repr(field.annotation), model.__name__
    token_field = ProtocolEventEnvelope.model_fields["attempt_token"]
    assert repr(token_field.annotation) == "AttemptToken"
    assert token_field.repr is False
    assert _EventHeader.model_config.get("extra") == "ignore"
    assert "attempt_token_hash" in _EventHeader.model_fields


def _scan(source: str) -> tuple[set[str], set[str], set[str]]:
    """The Stage 4 bare-name scan: import roots, first-party packages and every name
    the source mentions (bound, attribute or called); ambient calls are refused."""
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


def test_the_module_imports_only_pure_roots_and_uses_no_forbidden_name() -> None:
    source = Path(events.__file__ or "").read_text(encoding="utf-8")
    roots, packages, names = _scan(source)
    assert roots <= _PURE_ROOTS, sorted(roots - _PURE_ROOTS)
    assert packages <= {"domain", "adapters"}, sorted(packages)
    assert names & _STAGE4_BARE_NAMES == set()
    assert "subprocess" not in source
    assert "pending_bytes" in source


def test_the_bare_name_scan_finds_a_planted_name() -> None:
    """Plan Task 4 control: the scan that clears the module does see a Stage 4 bare
    name whether it is bound, read as an attribute or called."""
    planted = "Loader = compose(problem)\nresult = Loader.compose\n"
    assert _scan(planted)[2] & _STAGE4_BARE_NAMES == {"Loader", "compose", "problem"}
    # Control: the ambient-call refusal is live inside the scan.
    with pytest.raises(AssertionError):
        _scan("value = now()\n")


def test_task_four_launches_reads_and_connects_to_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("subprocess.Popen", _forbidden)
    monkeypatch.setattr("socket.create_connection", _forbidden)
    monkeypatch.setattr("os.getenv", _forbidden)
    outcomes, ledger = _feed([_encode(_typed("HEARTBEAT")), b"noise\n"])
    assert isinstance(outcomes[0], EventAccepted)
    assert isinstance(outcomes[1], EventRejected)
    ledger.summary()
    InvocationEventLedger.from_events(ledger.events)
    frame_protocol_lines(b"", b"a\nb", max_event_bytes=64)
    contamination_sample(b"noise", ATTEMPT_TOKEN)
    fold = BoundedStderrCapture(limit=16, token=ATTEMPT_TOKEN)
    fold.feed(b"x")
    fold.finish()


# --- Payload models ---------------------------------------------------------------


def _model(cls: type[Any], **updates: Any) -> Any:
    base = _PAYLOADS[
        next(name for name, model in _PAYLOAD_CLASSES.items() if model is cls)
    ]
    return cls.model_validate_json(json.dumps({**base, **updates}))


def test_every_payload_validates_in_both_modes_is_frozen_and_closed() -> None:
    for name, cls in _PAYLOAD_CLASSES.items():
        instance = cls.model_validate_json(json.dumps(_PAYLOADS[name]))
        assert cls.model_validate(instance.model_dump(mode="python")) == instance
        assert cls.model_validate_json(instance.model_dump_json()) == instance
        with pytest.raises(ValidationError, match="frozen"):
            setattr(instance, next(iter(cls.model_fields)), None)
        with pytest.raises(ValidationError, match="extra"):
            cls.model_validate_json(json.dumps({**_PAYLOADS[name], "unexpected": 1}))
        assert isinstance(instance.model_dump(mode="json"), dict)


def test_the_heartbeat_payload_bounds_its_counter_and_resource_observation() -> None:
    _model(HeartbeatPayload, activity_counter=MAX_COUNTER)
    _model(HeartbeatPayload, activity_counter=0)
    with pytest.raises(ValidationError, match="activity_counter"):
        _model(HeartbeatPayload, activity_counter=MAX_COUNTER + 1)
    with pytest.raises(ValidationError, match="activity_counter"):
        _model(HeartbeatPayload, activity_counter=-1)
    with pytest.raises(ValidationError, match="activity_counter"):
        _model(HeartbeatPayload, activity_counter=1.0)
    with pytest.raises(ValidationError, match="phase"):
        _model(HeartbeatPayload, phase="Warmup")
    observed = _model(
        HeartbeatPayload,
        resource_observation={"resident_memory_bytes": 1024, "cpu_seconds": "1.5"},
    )
    assert observed.resource_observation.cpu_seconds == Decimal("1.5")
    _model(HeartbeatPayload, resource_observation={"cpu_seconds": "0"})
    _model(HeartbeatPayload, resource_observation={"resident_memory_bytes": 0})
    with pytest.raises(ValidationError, match="at least one"):
        _model(HeartbeatPayload, resource_observation={})
    with pytest.raises(ValidationError, match="resident_memory_bytes"):
        _model(
            HeartbeatPayload,
            resource_observation={"resident_memory_bytes": MAX_DECLARED_SIZE_BYTES + 1},
        )
    with pytest.raises(ValidationError, match="cpu_seconds"):
        _model(HeartbeatPayload, resource_observation={"cpu_seconds": "-1"})
    with pytest.raises(ValidationError, match="cpu_seconds"):
        _model(HeartbeatPayload, resource_observation={"cpu_seconds": 1.5})


def test_the_progress_payload_orders_units_and_bounds_the_percentage() -> None:
    _model(ProgressPayload, percentage="100")
    _model(ProgressPayload, completed_units=10, total_units=10)
    absent = ProgressPayload.model_validate_json(
        json.dumps({"phase": "backtest", "completed_units": 0})
    )
    assert _missing(absent.total_units)
    assert _missing(absent.percentage)
    with pytest.raises(ValidationError, match="percentage"):
        _model(ProgressPayload, percentage="100.5")
    with pytest.raises(ValidationError, match="percentage"):
        _model(ProgressPayload, percentage="-1")
    with pytest.raises(ValidationError, match="total_units"):
        _model(ProgressPayload, completed_units=11, total_units=10)
    with pytest.raises(ValidationError, match="completed_units"):
        _model(ProgressPayload, completed_units=-1)
    with pytest.raises(ValidationError, match="completed_units"):
        _model(ProgressPayload, completed_units=MAX_COUNTER + 1, total_units=None)
    with pytest.raises(ValidationError, match="total_units"):
        _model(ProgressPayload, total_units=MAX_COUNTER + 1)


@pytest.mark.parametrize(
    "media_type",
    [
        "application/octet-stream",
        "text/plain",
        "application/vnd.crypto-lab.result+json",
        "x-a/b",
        "a" * 127 + "/" + "b" * 127,
    ],
)
def test_media_types_of_the_rfc_6838_shape_are_accepted(media_type: str) -> None:
    assert TypeAdapter(MediaType).validate_python(media_type) == media_type


@pytest.mark.parametrize(
    "media_type",
    [
        "Application/octet-stream",
        "application",
        "application/",
        "/json",
        "application/octet stream",
        "application/octet-stream; charset=utf-8",
        "a" * 128 + "/b",
        "application/" + "b" * 128,
        "",
        "-a/b",
        "a/b/c",
    ],
)
def test_media_types_outside_the_shape_are_rejected(media_type: str) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(MediaType).validate_python(media_type)


def test_the_artifact_payload_reuses_the_candidate_path_grammar_and_size_bound() -> (
    None
):
    _model(ArtifactProducedPayload, declared_size_bytes=MAX_DECLARED_SIZE_BYTES)
    for near_miss in ("../escape.bin", "C:/escape.bin", "results//x", "CON.bin", "a b"):
        with pytest.raises(ValidationError, match="relative_path"):
            _model(ArtifactProducedPayload, relative_path=near_miss)
    with pytest.raises(ValidationError, match="declared_size_bytes"):
        _model(ArtifactProducedPayload, declared_size_bytes=MAX_DECLARED_SIZE_BYTES + 1)
    with pytest.raises(ValidationError, match="declared_size_bytes"):
        _model(ArtifactProducedPayload, declared_size_bytes=-1)
    with pytest.raises(ValidationError, match="declared_sha256"):
        _model(ArtifactProducedPayload, declared_sha256="A" * 64)
    with pytest.raises(ValidationError, match="media_type"):
        _model(ArtifactProducedPayload, media_type="Application/Octet-Stream")
    with pytest.raises(ValidationError, match="artifact_kind"):
        _model(ArtifactProducedPayload, artifact_kind="Engine Native")


def test_the_final_result_payload_pins_the_pointer_shape() -> None:
    final = _model(FinalResultPayload)
    assert final.manifest_relative_path == "adapter-result-manifest.json"
    with pytest.raises(ValidationError, match="manifest_relative_path"):
        _model(FinalResultPayload, manifest_relative_path="../manifest.json")
    with pytest.raises(ValidationError, match="semantic_status"):
        _model(FinalResultPayload, semantic_status="DONE")
    with pytest.raises(ValidationError, match="source_adapter_result_manifest_hash"):
        _model(FinalResultPayload, source_adapter_result_manifest_hash="x" * 64)


def _diagnostic(**updates: Any) -> AdapterDiagnostic:
    return AdapterDiagnostic.model_validate_json(
        json.dumps({**_DIAGNOSTIC["diagnostic"], **updates})
    )


def test_an_adapter_diagnostic_reports_in_its_own_namespace_and_category() -> None:
    _diagnostic(error_code="ADAPTER.SOMETHING_ODD", category="ADAPTER_UNAVAILABILITY")
    _diagnostic(error_code="ENGINE.CRASH.DEEP", category="COMPATIBILITY")
    for spoofed in (
        "SECURITY.SPOOF",
        "PROTOCOL.MALFORMED_JSONL",
        "CORE.INVARIANT_VIOLATION",
        "ADAPTERX.ODD",
        "adapter.odd",
        "ADAPTER",
        "ADAPTER.",
    ):
        with pytest.raises(ValidationError, match="error_code"):
            _diagnostic(error_code=spoofed)
    for core_category in ("PROTOCOL", "SECURITY", "INTERNAL_INVARIANT", "TIMEOUT"):
        with pytest.raises(ValidationError, match="category"):
            _diagnostic(category=core_category)
    with pytest.raises(ValidationError, match="severity"):
        _diagnostic(severity="FATAL")


def test_an_adapter_diagnostic_bounds_its_causes_details_and_message() -> None:
    causes = tuple(sorted(_event_id(index) for index in range(MAX_CAUSAL_EVENT_IDS)))
    assert _diagnostic(causal_event_ids=list(causes)).causal_event_ids == causes
    with pytest.raises(ValidationError, match="causal_event_ids"):
        _diagnostic(causal_event_ids=[*causes, _event_id("one more")])
    with pytest.raises(ValidationError, match="sorted"):
        _diagnostic(causal_event_ids=list(reversed(causes[:2])))
    with pytest.raises(ValidationError, match="unique"):
        _diagnostic(causal_event_ids=[causes[0], causes[0]])
    with pytest.raises(ValidationError, match="secret"):
        _diagnostic(details={"attempt_token": "x"})
    with pytest.raises(ValidationError, match="details"):
        _diagnostic(details={"deep": "x" * 3000})
    with pytest.raises(ValidationError, match="message"):
        _diagnostic(message="")
    with pytest.raises(ValidationError, match="message"):
        _diagnostic(message="x" * 1025)
    assert AdapterDiagnostic.model_fields["causal_event_ids"].json_schema_extra == {
        "uniqueItems": True
    }


def test_a_protocol_warning_sorts_its_prevented_levels_and_shares_the_namespace() -> (
    None
):
    warning = ProtocolWarning.model_validate_json(json.dumps(_WARNING["warning"]))
    assert warning.prevented_comparison_levels == ("LEVEL_3",)
    payload = {**_WARNING["warning"], "prevented_comparison_levels": []}
    ProtocolWarning.model_validate_json(json.dumps(payload))
    payload["prevented_comparison_levels"] = ["LEVEL_1", "LEVEL_2", "LEVEL_3"]
    ProtocolWarning.model_validate_json(json.dumps(payload))
    payload["prevented_comparison_levels"] = ["LEVEL_2", "LEVEL_1"]
    with pytest.raises(ValidationError, match="sorted"):
        ProtocolWarning.model_validate_json(json.dumps(payload))
    payload["prevented_comparison_levels"] = ["LEVEL_1", "LEVEL_1"]
    with pytest.raises(ValidationError, match="unique"):
        ProtocolWarning.model_validate_json(json.dumps(payload))
    payload = {**_WARNING["warning"], "warning_code": "PROTOCOL.SPOOF"}
    with pytest.raises(ValidationError, match="warning_code"):
        ProtocolWarning.model_validate_json(json.dumps(payload))
    payload = {**_WARNING["warning"], "impact": ""}
    with pytest.raises(ValidationError, match="impact"):
        ProtocolWarning.model_validate_json(json.dumps(payload))
    extra = ProtocolWarning.model_fields[
        "prevented_comparison_levels"
    ].json_schema_extra
    assert isinstance(extra, dict)
    assert extra.get("uniqueItems") is True
    assert len(extra["enum"]) == 8  # type: ignore[arg-type]


# --- The wire envelope --------------------------------------------------------------


def test_a_conformant_envelope_validates_hides_its_token_and_round_trips() -> None:
    line = _line()[:-1]
    envelope = ProtocolEventEnvelope.model_validate_json(line)
    assert envelope.event_type is ProtocolEventType.HEARTBEAT
    assert isinstance(envelope.payload, HeartbeatPayload)
    assert envelope.attempt_token == ATTEMPT_TOKEN
    assert ATTEMPT_TOKEN not in repr(envelope)
    assert ATTEMPT_TOKEN not in str(envelope)
    assert ATTEMPT_TOKEN in envelope.model_dump_json()
    for mode in _MODES:
        dumped = envelope.model_dump(mode=mode)
        assert dumped["attempt_token"] == ATTEMPT_TOKEN
    assert ProtocolEventEnvelope.model_validate(envelope.model_dump()) == envelope
    assert canonical_json_bytes(envelope) == line
    with pytest.raises(ValidationError, match="frozen"):
        envelope.sequence = 2


@pytest.mark.parametrize("event_type", list(_PAYLOADS))
def test_every_event_type_reaches_exactly_its_own_payload_branch(
    event_type: str,
) -> None:
    envelope = ProtocolEventEnvelope.model_validate_json(
        _encode(_typed(event_type))[:-1]
    )
    assert type(envelope.payload) is _PAYLOAD_CLASSES[event_type]
    for other, payload in _PAYLOADS.items():
        if other == event_type:
            continue
        with pytest.raises(ValidationError, match="event_type"):
            ProtocolEventEnvelope.model_validate_json(
                _encode(_typed(event_type, payload=payload))[:-1]
            )


def test_the_envelope_rejects_unknown_types_fields_and_out_of_range_sequences() -> None:
    with pytest.raises(ValidationError, match="event_type"):
        ProtocolEventEnvelope.model_validate_json(_line(event_type="TELEMETRY")[:-1])
    with pytest.raises(ValidationError, match="event_type"):
        ProtocolEventEnvelope.model_validate_json(_line(event_type="heartbeat")[:-1])
    with pytest.raises(ValidationError, match="extra"):
        ProtocolEventEnvelope.model_validate_json(_line(unexpected=1)[:-1])
    with pytest.raises(ValidationError, match="sequence"):
        ProtocolEventEnvelope.model_validate_json(_line(sequence=0)[:-1])
    with pytest.raises(ValidationError, match="sequence"):
        ProtocolEventEnvelope.model_validate_json(_line(sequence=MAX_SEQUENCE + 1)[:-1])
    ProtocolEventEnvelope.model_validate_json(_line(sequence=MAX_SEQUENCE)[:-1])
    with pytest.raises(ValidationError, match="attempt_token"):
        ProtocolEventEnvelope.model_validate_json(_line(attempt_token="x" * 5)[:-1])
    document = _document()
    del document["attempt_token"]
    with pytest.raises(ValidationError, match="attempt_token"):
        ProtocolEventEnvelope.model_validate_json(_encode(document)[:-1])
    with pytest.raises(ValidationError, match="timestamp_utc"):
        ProtocolEventEnvelope.model_validate_json(
            _line(timestamp_utc="2026-02-30T00:00:00Z")[:-1]
        )
    with pytest.raises(ValidationError, match="protocol_version"):
        ProtocolEventEnvelope.model_validate_json(_line(protocol_version="1.0.1")[:-1])


def _schema_pairing_clauses(schema: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        clause
        for clause in schema.get("allOf", [])
        if "if" in clause and "event_type" in clause["if"].get("properties", {})
    ]


@pytest.mark.parametrize("model", [ProtocolEventEnvelope, RunEvent])
def test_the_event_schemas_publish_the_pairing_and_are_closed_in_both_modes(
    model: type[Any],
) -> None:
    validation = model.model_json_schema(mode="validation")
    serialization = model.model_json_schema(mode="serialization")
    assert validation == serialization
    Draft202012Validator.check_schema(validation)
    assert validation["additionalProperties"] is False
    for name, definition in validation["$defs"].items():
        if definition.get("type") == "object":
            assert definition.get("additionalProperties") is False, name
    clauses = _schema_pairing_clauses(validation)
    assert [
        clause["if"]["properties"]["event_type"]["const"] for clause in clauses
    ] == [member.value for member in ProtocolEventType]
    branches = validation["properties"]["payload"]["anyOf"]
    assert len(branches) == 6
    assert [clause["then"]["properties"]["payload"]["$ref"] for clause in clauses] == [
        branch["$ref"] for branch in branches
    ]
    for reference in (branch["$ref"] for branch in branches):
        assert reference.startswith("#/$defs/")
        assert reference.removeprefix("#/$defs/") in validation["$defs"]
    assert "UtcDateTime" not in validation["$defs"]
    assert all(not pattern.endswith("$") for pattern in _patterns(validation))


def _patterns(node: object) -> list[str]:
    if isinstance(node, dict):
        found = [node["pattern"]] if isinstance(node.get("pattern"), str) else []
        for value in node.values():
            found.extend(_patterns(value))
        return found
    if isinstance(node, list):
        return [pattern for item in node for pattern in _patterns(item)]
    return []


def test_the_published_pairing_rejects_a_swapped_payload_and_accepts_each_member() -> (
    None
):
    validator = Draft202012Validator(ProtocolEventEnvelope.model_json_schema())
    for event_type in _PAYLOADS:
        assert validator.is_valid(_typed(event_type))
        for other, payload in _PAYLOADS.items():
            if other != event_type:
                assert not validator.is_valid(_typed(event_type, payload=payload))
    assert not validator.is_valid(_document(event_type="TELEMETRY"))


# --- RunEvent -----------------------------------------------------------------------


def test_a_run_event_carries_the_hash_not_the_token_and_recomputes_its_content() -> (
    None
):
    event = _accepted(_parse(_line()))
    assert event.attempt_token_hash == attempt_token_hash(ATTEMPT_TOKEN)
    assert ATTEMPT_TOKEN not in event.model_dump_json()
    assert ATTEMPT_TOKEN not in repr(event)
    assert event.received_at_utc == _RECEIVED
    assert event.wire_event_hash == sha256_bytes(_line()[:-1])
    assert event.content_hash == run_event_content_hash(event)
    for mode in _MODES:
        dumped = event.model_dump(mode=mode)
        assert "attempt_token" not in dumped
    assert RunEvent.model_validate(event.model_dump(mode="python")) == event
    assert RunEvent.model_validate_json(event.model_dump_json()) == event
    with pytest.raises(ValidationError, match="frozen"):
        event.sequence = 2
    with pytest.raises(ValidationError, match="extra"):
        RunEvent.model_validate(
            {**event.model_dump(mode="python"), "attempt_token": ATTEMPT_TOKEN}
        )
    stale = event.model_dump(mode="python")
    stale["content_hash"] = _OTHER_HASH
    with pytest.raises(ValidationError, match="content_hash"):
        RunEvent.model_validate(stale)
    swapped = event.model_dump(mode="python")
    swapped["payload"] = ProgressPayload.model_validate_json(json.dumps(_PROGRESS))
    with pytest.raises(ValidationError, match="event_type"):
        RunEvent.model_validate(swapped)
    with pytest.raises(ValidationError, match="wire_event_hash"):
        RunEvent.model_validate(
            {**event.model_dump(mode="python"), "wire_event_hash": "x"}
        )


def test_the_content_hash_golden_is_the_profile_over_the_ten_content_fields() -> None:
    event = _accepted(_parse(_line()))
    payload = {
        "schema_version": "1.0.0",
        "protocol_version": "1.0.0",
        "event_id": _event_id(f"{INVOCATION_ID}:1"),
        "invocation_id": INVOCATION_ID,
        "run_id": RUN_ID,
        "attempt_token_hash": attempt_token_hash(ATTEMPT_TOKEN),
        "sequence": 1,
        "event_type": "HEARTBEAT",
        "timestamp_utc": _STAMP,
        "payload": {"activity_counter": 1, "phase": "warmup"},
    }
    independent = _stdlib_digest(
        {
            "schema_version": "1.0.0",
            "hashing_profile": "run-event-content/v1",
            "payload": payload,
        }
    )
    assert event.content_hash == independent
    assert event.content_hash == profile_hash(
        HashingProfile.RUN_EVENT_CONTENT_V1,
        payload,  # type: ignore[arg-type]
    )
    assert event.content_hash == _CONTENT_GOLDEN, event.content_hash
    assert event.content_hash != event.wire_event_hash
    assert event.content_hash != sha256_bytes(canonical_json_bytes(event))


def test_the_content_hash_ignores_the_receipt_instant_and_the_wire_bytes() -> None:
    event = _accepted(_parse(_line()))
    later = _run_event(received_at_utc=_RECEIVED + timedelta(hours=1))
    rewired = _run_event(wire_event_hash=_OTHER_HASH)
    assert later.content_hash == event.content_hash
    assert rewired.content_hash == event.content_hash
    assert later != event
    assert rewired != event
    # The same content from a differently serialized line.
    spaced = json.dumps(_document(), indent=2).replace("\n", "").encode() + b"\n"
    assert spaced != _line()
    other = _accepted(_parse(spaced))
    assert other.content_hash == event.content_hash
    assert other.wire_event_hash != event.wire_event_hash


@pytest.mark.parametrize(
    "changes",
    [
        {"event_id": _event_id("other")},
        {"invocation_id": OTHER_INVOCATION_ID},
        {"run_id": OTHER_RUN_ID},
        {"attempt_token_hash": attempt_token_hash(_WRONG_TOKEN)},
        {"sequence": 2},
        {"timestamp_utc": datetime(2026, 9, 11, 10, 0, 2, tzinfo=UTC)},
        {
            "payload": HeartbeatPayload.model_validate_json(
                json.dumps({"activity_counter": 2, "phase": "warmup"})
            )
        },
        {
            "event_type": ProtocolEventType.PROGRESS,
            "payload": ProgressPayload.model_validate_json(json.dumps(_PROGRESS)),
        },
    ],
    ids=[
        "event_id",
        "invocation_id",
        "run_id",
        "attempt_token_hash",
        "sequence",
        "timestamp_utc",
        "payload",
        "event_type",
    ],
)
def test_every_material_field_moves_the_content_hash(changes: dict[str, Any]) -> None:
    event = _accepted(_parse(_line()))
    changed = _run_event(**changes)
    assert changed.content_hash != event.content_hash
    payload = changed.model_dump(mode="python")
    payload["content_hash"] = event.content_hash
    with pytest.raises(ValidationError, match="content_hash") as captured:
        RunEvent.model_validate(payload)
    assert ATTEMPT_TOKEN not in str(captured.value)


def test_the_content_hash_is_invariant_under_key_permutation_of_the_dump() -> None:
    event = _accepted(_parse(_line()))
    dumped = event.model_dump(mode="python")
    permuted = {name: dumped[name] for name in reversed(list(dumped))}
    assert RunEvent.model_validate(permuted) == event
    assert (
        run_event_content_hash(RunEvent.model_validate(permuted)) == event.content_hash
    )


def test_run_event_content_hash_takes_a_run_event() -> None:
    with pytest.raises(TypeError, match="RunEvent"):
        run_event_content_hash(ProtocolEventEnvelope.model_validate_json(_line()[:-1]))  # type: ignore[arg-type]


# --- Framing (plan 7.1) -------------------------------------------------------------


def test_an_lf_terminated_line_is_accepted_and_hashed_without_its_terminator() -> None:
    line = _line()
    outcome = _parse(line)
    assert isinstance(outcome, EventAccepted)
    assert outcome.redactions == 0
    assert outcome.event.wire_event_hash == sha256_bytes(line[:-1])
    assert outcome.event.sequence == 1
    assert outcome.event.event_type is ProtocolEventType.HEARTBEAT
    assert outcome.event.timestamp_utc == datetime(2026, 9, 11, 10, 0, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    "line",
    [
        _encode(_document(), b"\r\n"),
        b"\xef\xbb\xbf" + _line(),
        b"\n",
        _line()[:-1],
        b"starting engine\n",
        b" " + _line(),
        b"[]\n",
        b"\xff\xfe\n",
        b"{\xff\xfe}\n",
        _line().replace(b'"phase":"warmup"', b'"phase":"warm\rup"'),
        _line()[:-1] + b"\n" + _line(),
        b"",
    ],
    ids=[
        "crlf",
        "bom",
        "empty",
        "unterminated",
        "text",
        "leading-space",
        "array",
        "invalid-utf8",
        "invalid-utf8-in-object",
        "carriage-return-inside",
        "two-lines",
        "no-bytes",
    ],
)
def test_framing_violations_are_stdout_contamination(line: bytes) -> None:
    outcome = _parse(line)
    assert _code(outcome) == PROTOCOL_STDOUT_CONTAMINATION
    assert isinstance(outcome, EventRejected)
    assert outcome.sample.byte_length == len(line.removesuffix(b"\n"))
    assert outcome.sample.source_hash == sha256_bytes(line.removesuffix(b"\n"))
    # No verified token exists before the identity phase, so no sample bytes leave.
    assert _missing(outcome.sample.sample)


@pytest.mark.parametrize(
    "line",
    [
        b'{"schema_version": \n',
        b"{\n",
        _line()[:-1] + b" {}\n",
        _line()[:-1] + b",\n",
        b'{"sequence": NaN}\n',
        b'{"sequence": Infinity}\n',
        b'{"sequence": -Infinity}\n',
        _line(unexpected=1),
        _line(event_type="TELEMETRY"),
        _line(event_type="heartbeat"),
        _line(event_type=7),
        _line(payload=1),
        _line(payload=_PROGRESS),
        _line(payload={"activity_counter": True, "phase": "x"}),
        _line(timestamp_utc="2026-02-30T00:00:00Z"),
        _line(protocol_version=1),
        _line(schema_version=None),
        b'{"a":' + b"[" * 100_000 + b"\n",
    ],
    ids=[
        "truncated",
        "open-brace",
        "trailing-object",
        "trailing-comma",
        "nan",
        "infinity",
        "negative-infinity",
        "unknown-field",
        "unknown-event-type",
        "lowercase-event-type",
        "numeric-event-type",
        "scalar-payload",
        "wrong-branch-payload",
        "bool-counter",
        "impossible-instant",
        "numeric-version",
        "null-version",
        "deep-nesting",
    ],
)
def test_json_and_schema_failures_of_a_framed_line_are_malformed(line: bytes) -> None:
    assert _code(_parse(line)) == PROTOCOL_MALFORMED_JSONL


def test_an_empty_stream_and_an_empty_remainder_are_normal() -> None:
    complete, pending_bytes = frame_protocol_lines(
        b"", b"", max_event_bytes=MAX_EVENT_LINE_BYTES
    )
    assert complete == ()
    assert pending_bytes == b""
    complete, pending_bytes = frame_protocol_lines(
        b"", _line(), max_event_bytes=MAX_EVENT_LINE_BYTES
    )
    assert complete == (_line(),)
    assert pending_bytes == b""


def test_the_framer_splits_on_lf_only_carries_the_fragment_and_bounds_it() -> None:
    assert frame_protocol_lines(b"", b"a\nb", max_event_bytes=64) == ((b"a\n",), b"b")
    assert frame_protocol_lines(b"b", b"c\n\nd", max_event_bytes=64) == (
        (b"bc\n", b"\n"),
        b"d",
    )
    assert frame_protocol_lines(b"", b"x\r\ny\n", max_event_bytes=64) == (
        (b"x\r\n", b"y\n"),
        b"",
    )
    # An unterminated tail over the limit is emitted early, without its terminator,
    # so the parser rejects it as too large and memory stays bounded.
    assert frame_protocol_lines(b"", b"z" * 10, max_event_bytes=8) == (
        (b"z" * 10,),
        b"",
    )
    assert frame_protocol_lines(b"z" * 5, b"z" * 4, max_event_bytes=8) == (
        (b"z" * 9,),
        b"",
    )
    assert frame_protocol_lines(b"", b"z" * 8, max_event_bytes=8) == ((), b"z" * 8)
    assert frame_protocol_lines(b"", b"z" * 9 + b"\nq", max_event_bytes=8) == (
        (b"z" * 9 + b"\n",),
        b"q",
    )
    with pytest.raises(TypeError, match="bytes"):
        frame_protocol_lines("", b"x", max_event_bytes=8)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="bytes"):
        frame_protocol_lines(b"", "x", max_event_bytes=8)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="max_event_bytes"):
        frame_protocol_lines(b"", b"x", max_event_bytes=True)
    with pytest.raises(ValueError, match="max_event_bytes"):
        frame_protocol_lines(b"", b"x", max_event_bytes=0)
    with pytest.raises(ValueError, match="max_event_bytes"):
        frame_protocol_lines(b"", b"x", max_event_bytes=MAX_EVENT_LINE_BYTES + 1)


def test_a_trailing_fragment_fed_at_end_of_stream_is_contamination() -> None:
    complete, pending_bytes = frame_protocol_lines(
        b"", _line() + _line(sequence=2)[:10], max_event_bytes=MAX_EVENT_LINE_BYTES
    )
    assert complete == (_line(),)
    assert pending_bytes == _line(sequence=2)[:10]
    outcome = _parse(pending_bytes)
    assert _code(outcome) == PROTOCOL_STDOUT_CONTAMINATION


# --- The byte limit (plan 7.1 rule 4) ------------------------------------------------


def test_a_line_over_the_limit_is_too_large_and_never_decoded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(json, "loads", _forbidden)
    line = _line()
    padded = line[:-1] + b"\xff\xfe" + b"\n"  # also invalid UTF-8
    outcome = _parse(padded, max_event_bytes=len(padded) - 2)
    assert _code(outcome) == PROTOCOL_EVENT_TOO_LARGE
    assert isinstance(outcome, EventRejected)
    assert outcome.sample.byte_length == len(padded) - 1
    assert outcome.sample.source_hash == sha256_bytes(padded[:-1])
    assert _missing(outcome.sample.sample)
    # The unterminated over-limit tail the framer emits early is too large as well.
    assert _code(_parse(b"z" * 20, max_event_bytes=8)) == PROTOCOL_EVENT_TOO_LARGE


def test_the_terminator_does_not_count_and_the_limit_is_inclusive() -> None:
    line = _line()
    assert isinstance(_parse(line, max_event_bytes=len(line) - 1), EventAccepted)
    assert (
        _code(_parse(line, max_event_bytes=len(line) - 2)) == PROTOCOL_EVENT_TOO_LARGE
    )


# --- Versions (plan 5.1, 7.4) -------------------------------------------------------


@pytest.mark.parametrize(
    "updates",
    [
        {"protocol_version": "2.0.0"},
        {"schema_version": "2.0.0"},
        {"protocol_version": "1.0.1", "schema_version": "1.0.0"},
        {"protocol_version": "0.9.0", "invocation_id": OTHER_INVOCATION_ID},
    ],
    ids=["protocol", "schema", "patch", "version-before-identity"],
)
def test_a_readable_unsupported_version_is_unsupported_version(
    updates: dict[str, Any],
) -> None:
    assert _code(_parse(_line(**updates))) == PROTOCOL_UNSUPPORTED_VERSION


# --- Identity and sequence (plan 7.3) ----------------------------------------------


@pytest.mark.parametrize(
    "updates",
    [
        {"invocation_id": OTHER_INVOCATION_ID},
        {"invocation_id": "inv_not-a-uuid"},
        {"invocation_id": 7},
        {"invocation_id": None},
        {"run_id": OTHER_RUN_ID},
        {"run_id": ["x"]},
        {"attempt_token": _WRONG_TOKEN},
        {"attempt_token": 12345},
        {"attempt_token": "x" * 1025},
        {"attempt_token": ""},
        {"sequence": 0},
        {"sequence": -1},
        {"sequence": MAX_SEQUENCE + 1},
        {"sequence": 10**30},
        {"sequence": 2},
        {"sequence": "1"},
        {"sequence": 1.0},
        {"sequence": None},
        {"invocation_id": OTHER_INVOCATION_ID, "payload": {"activity_counter": -1}},
        {"attempt_token": _WRONG_TOKEN, "payload": {"activity_counter": -1}},
        {"attempt_token": _WRONG_TOKEN, "event_type": "TELEMETRY"},
        {"attempt_token": _WRONG_TOKEN, "unexpected": 1},
    ],
    ids=[
        "foreign-invocation",
        "malformed-invocation",
        "numeric-invocation",
        "null-invocation",
        "foreign-run",
        "list-run",
        "wrong-token",
        "numeric-token",
        "overlong-token",
        "empty-token",
        "sequence-zero",
        "sequence-negative",
        "sequence-over-max",
        "sequence-huge",
        "sequence-gap",
        "sequence-string",
        "sequence-float",
        "sequence-null",
        "identity-before-malformed-payload",
        "token-before-malformed-payload",
        "token-before-unknown-type",
        "token-before-unknown-field",
    ],
)
def test_identity_and_sequence_failures_on_a_fresh_invocation(
    updates: dict[str, Any],
) -> None:
    document = _document(**updates)
    for key, value in updates.items():
        if value is None:
            del document[key]
    outcome = _parse(_encode(document))
    assert _code(outcome) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    assert isinstance(outcome, EventRejected)
    dumped = outcome.model_dump_json()
    assert ATTEMPT_TOKEN not in dumped
    assert _WRONG_TOKEN not in dumped


def test_the_sample_exists_only_once_the_line_token_is_verified() -> None:
    """Plan 7.6 and specification 14.7: before the identity phase has verified the
    line's token no removal can be proven, so only the byte facts are recorded; a
    sequence failure comes after that proof and carries the redacted sample."""
    before = _parse(_line(invocation_id=OTHER_INVOCATION_ID))
    assert isinstance(before, EventRejected)
    assert _missing(before.sample.sample)
    wrong = _parse(_line(attempt_token=_WRONG_TOKEN))
    assert isinstance(wrong, EventRejected)
    assert _missing(wrong.sample.sample)
    after = _parse(_line(sequence=5))
    assert isinstance(after, EventRejected)
    assert _code(after) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    assert not _missing(after.sample.sample)
    assert ATTEMPT_TOKEN not in after.sample.sample
    assert REDACTION_PLACEHOLDER in after.sample.sample


def test_a_missing_or_misspelled_invocation_key_is_an_identity_violation() -> None:
    assert _code(_parse(b"{}\n")) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    document = _document()
    del document["invocation_id"]
    assert _code(_parse(_encode(document))) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    document = _document()
    document["invocationId"] = document.pop("invocation_id")
    assert _code(_parse(_encode(document))) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION


def test_a_non_member_type_is_malformed_but_a_disallowed_member_is_identity() -> None:
    assert _code(_parse(_line(event_type="TELEMETRY"))) == PROTOCOL_MALFORMED_JSONL
    assert (
        _code(_parse(_encode(_typed("ARTIFACT_PRODUCED")), kind=CommandKind.VALIDATE))
        == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    )
    assert (
        _code(_parse(_encode(_typed("FINAL_RESULT")), kind=CommandKind.VALIDATE))
        == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    )
    # The kind test precedes the payload shape: a disallowed member with a malformed
    # payload still reports identity.
    assert (
        _code(
            _parse(
                _line(event_type="FINAL_RESULT", payload={"x": 1}),
                kind=CommandKind.VALIDATE,
            )
        )
        == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    )
    for event_type in ("HEARTBEAT", "PROGRESS", "WARNING", "DIAGNOSTIC"):
        assert isinstance(
            _parse(_encode(_typed(event_type)), kind=CommandKind.VALIDATE),
            EventAccepted,
        )


def test_a_wrong_header_token_is_reported_as_identity_with_only_its_hash_read() -> None:
    outcome = _parse(
        _line(attempt_token=_WRONG_TOKEN, payload={"activity_counter": -1})
    )
    assert _code(outcome) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    assert isinstance(outcome, EventRejected)
    dumped = outcome.model_dump_json()
    assert _WRONG_TOKEN not in dumped
    assert ATTEMPT_TOKEN not in dumped
    assert "attempt_token" not in _EventHeader.model_fields
    header = _EventHeader.model_validate({"attempt_token_hash": _HASH, "ignored": 1})
    assert header.attempt_token_hash == _HASH
    with pytest.raises(ValidationError):
        _EventHeader.model_validate({"attempt_token_hash": "x"})


def test_an_identical_replay_returns_the_stored_event_and_advances_nothing() -> None:
    clock = CountingClock(_RECEIVED)
    first = _parse(_line(), clock=clock)
    assert isinstance(first, EventAccepted)
    assert clock.reads == 1
    ledger = InvocationEventLedger().accept(first)
    clock.advance(3600)
    replay = _parse(_line(), ledger=ledger, clock=clock)
    assert clock.reads == 2
    assert isinstance(replay, EventReplayed)
    assert replay.event is first.event
    assert replay.event.received_at_utc == _RECEIVED
    assert ledger.accept(replay) is ledger
    # A differently serialized identical line is the same content.
    spaced = json.dumps(_document(), indent=2).replace("\n", "").encode() + b"\n"
    respaced = _parse(spaced, ledger=ledger, clock=clock)
    assert isinstance(respaced, EventReplayed)
    assert respaced.event is first.event


def test_a_conflicting_duplicate_sequence_is_an_identity_violation() -> None:
    _, ledger = _feed([_line()])
    conflict = _parse(
        _line(payload={"activity_counter": 2, "phase": "warmup"}), ledger=ledger
    )
    assert _code(conflict) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    # Same content but another event_id or timestamp is also a conflict.
    other_id = _parse(_line(event_id=_event_id("other")), ledger=ledger)
    assert _code(other_id) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    other_stamp = _parse(_line(timestamp_utc="2026-09-11T10:00:02Z"), ledger=ledger)
    assert _code(other_stamp) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION


def test_a_gap_after_accepted_events_is_an_identity_violation() -> None:
    _, ledger = _feed([_line(), _encode(_typed("PROGRESS", 2))])
    assert _code(_parse(_encode(_typed("HEARTBEAT", 4)), ledger=ledger)) == (
        PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    )
    assert isinstance(
        _parse(_encode(_typed("HEARTBEAT", 3)), ledger=ledger), EventAccepted
    )


# --- Redaction and the path-located classification (plan 7.4, 7.6) ------------------


def test_a_token_in_a_message_is_redacted_and_the_event_is_still_accepted() -> None:
    tokened = {
        "warning": {
            **_WARNING["warning"],
            "message": f"engine said {ATTEMPT_TOKEN}",
            "impact": f"{ATTEMPT_TOKEN} and {ATTEMPT_TOKEN}",
        }
    }
    outcome = _parse(_line(event_type="WARNING", payload=tokened))
    assert isinstance(outcome, EventAccepted)
    assert outcome.redactions == 3
    warning = outcome.event.payload
    assert isinstance(warning, WarningPayload)
    assert warning.warning.message == f"engine said {REDACTION_PLACEHOLDER}"
    assert warning.warning.impact == (
        f"{REDACTION_PLACEHOLDER} and {REDACTION_PLACEHOLDER}"
    )
    assert ATTEMPT_TOKEN not in outcome.model_dump_json()
    assert ATTEMPT_TOKEN not in repr(outcome)


def test_a_token_in_a_details_key_or_value_cannot_reach_the_event() -> None:
    in_value = {
        "diagnostic": {
            **_DIAGNOSTIC["diagnostic"],
            "details": {"engine_log": f"token={ATTEMPT_TOKEN}"},
        }
    }
    outcome = _parse(_line(event_type="DIAGNOSTIC", payload=in_value))
    assert isinstance(outcome, EventAccepted)
    assert outcome.redactions == 1
    assert ATTEMPT_TOKEN not in outcome.model_dump_json()
    in_key = {
        "diagnostic": {
            **_DIAGNOSTIC["diagnostic"],
            "details": {f"k{ATTEMPT_TOKEN}": "v"},
        }
    }
    rejected = _parse(_line(event_type="DIAGNOSTIC", payload=in_key))
    assert _code(rejected) == PROTOCOL_MALFORMED_JSONL
    assert ATTEMPT_TOKEN not in rejected.model_dump_json()


def test_a_token_as_the_heartbeat_phase_is_malformed_only_because_of_redaction() -> (
    None
):
    line = _line(
        attempt_token=_IDENTIFIER_TOKEN,
        payload={"activity_counter": 1, "phase": _IDENTIFIER_TOKEN},
    )
    # Control: without redaction the same line is a valid wire envelope.
    envelope = ProtocolEventEnvelope.model_validate_json(line[:-1])
    assert isinstance(envelope.payload, HeartbeatPayload)
    assert envelope.payload.phase == _IDENTIFIER_TOKEN
    outcome = _parse(line, token=_IDENTIFIER_TOKEN)
    assert _code(outcome) == PROTOCOL_MALFORMED_JSONL
    assert _IDENTIFIER_TOKEN not in outcome.model_dump_json()
    assert isinstance(outcome, EventRejected)
    assert not _missing(outcome.sample.sample)
    assert _IDENTIFIER_TOKEN not in outcome.sample.sample
    assert REDACTION_PLACEHOLDER in outcome.sample.sample
    # Control: the envelope's own attempt_token key is not redacted, so a conformant
    # line under the same token is accepted.
    accepted = _parse(_line(attempt_token=_IDENTIFIER_TOKEN), token=_IDENTIFIER_TOKEN)
    assert isinstance(accepted, EventAccepted)
    assert accepted.redactions == 0


def test_a_token_as_the_declared_path_is_a_path_boundary_violation() -> None:
    line = _line(
        attempt_token=_IDENTIFIER_TOKEN,
        event_type="ARTIFACT_PRODUCED",
        payload={**_ARTIFACT, "relative_path": _IDENTIFIER_TOKEN},
    )
    envelope = ProtocolEventEnvelope.model_validate_json(line[:-1])
    assert isinstance(envelope.payload, ArtifactProducedPayload)
    outcome = _parse(line, token=_IDENTIFIER_TOKEN)
    assert _code(outcome) == ARTIFACT_PATH_BOUNDARY_VIOLATION
    assert isinstance(outcome, EventRejected)
    assert outcome.diagnostic.category is DiagnosticCategory.ARTIFACT_CORRUPTION
    assert _IDENTIFIER_TOKEN not in outcome.model_dump_json()
    assert not _missing(outcome.sample.sample)


@pytest.mark.parametrize(
    ("event_type", "field", "value"),
    [
        ("ARTIFACT_PRODUCED", "relative_path", "../escape.bin"),
        ("ARTIFACT_PRODUCED", "relative_path", "C:/escape.bin"),
        ("ARTIFACT_PRODUCED", "relative_path", "results/../x.bin"),
        ("ARTIFACT_PRODUCED", "relative_path", "results/CON"),
        ("ARTIFACT_PRODUCED", "relative_path", ""),
        ("ARTIFACT_PRODUCED", "relative_path", "a" * 513),
        ("FINAL_RESULT", "manifest_relative_path", "/manifest.json"),
        ("FINAL_RESULT", "manifest_relative_path", "..\\manifest.json"),
    ],
)
def test_a_path_near_miss_is_a_path_boundary_violation(
    event_type: str, field: str, value: str
) -> None:
    payload = {**_PAYLOADS[event_type], field: value}
    assert _code(_parse(_encode(_typed(event_type, payload=payload)))) == (
        ARTIFACT_PATH_BOUNDARY_VIOLATION
    )


def test_an_absent_path_is_malformed_while_an_invalid_present_path_is_a_violation() -> (
    None
):
    """Plan 7.4: an error located at a path field is the path violation whatever its
    shape; an absent path is a missing field, a schema failure."""
    payload = {**_ARTIFACT, "relative_path": 7}
    assert _code(_parse(_encode(_typed("ARTIFACT_PRODUCED", payload=payload)))) == (
        ARTIFACT_PATH_BOUNDARY_VIOLATION
    )
    absent = dict(_ARTIFACT)
    del absent["relative_path"]
    assert _code(_parse(_encode(_typed("ARTIFACT_PRODUCED", payload=absent)))) == (
        PROTOCOL_MALFORMED_JSONL
    )
    # A path-shaped payload under the wrong event type is a wrong-branch payload.
    assert (
        _code(
            _parse(
                _encode(
                    _typed("HEARTBEAT", payload={**_ARTIFACT, "relative_path": "../x"})
                )
            )
        )
        == PROTOCOL_MALFORMED_JSONL
    )


@pytest.mark.parametrize(
    ("event_type", "payload"),
    [
        ("HEARTBEAT", {"activity_counter": MAX_COUNTER + 1, "phase": "x"}),
        ("PROGRESS", {**_PROGRESS, "percentage": "101"}),
        ("PROGRESS", {**_PROGRESS, "completed_units": 11, "total_units": 10}),
        ("ARTIFACT_PRODUCED", {**_ARTIFACT, "media_type": "Application/Octet"}),
        (
            "DIAGNOSTIC",
            {
                "diagnostic": {
                    **_DIAGNOSTIC["diagnostic"],
                    "error_code": "SECURITY.SPOOF",
                }
            },
        ),
        (
            "DIAGNOSTIC",
            {"diagnostic": {**_DIAGNOSTIC["diagnostic"], "category": "PROTOCOL"}},
        ),
        (
            "DIAGNOSTIC",
            {
                "diagnostic": {
                    **_DIAGNOSTIC["diagnostic"],
                    "causal_event_ids": sorted(
                        _event_id(index) for index in range(MAX_CAUSAL_EVENT_IDS + 1)
                    ),
                }
            },
        ),
        (
            "WARNING",
            {"warning": {**_WARNING["warning"], "warning_code": "CORE.SPOOF"}},
        ),
        ("FINAL_RESULT", {**_FINAL, "semantic_status": "DONE"}),
    ],
    ids=[
        "counter-ceiling",
        "percentage-over-100",
        "total-below-completed",
        "uppercase-media-type",
        "core-namespace-code",
        "core-category",
        "too-many-causes",
        "core-namespace-warning",
        "unknown-status",
    ],
)
def test_payload_bound_and_namespace_violations_are_malformed(
    event_type: str, payload: dict[str, Any]
) -> None:
    assert _code(_parse(_encode(_typed(event_type, payload=payload)))) == (
        PROTOCOL_MALFORMED_JSONL
    )


# --- Hostile bytes never raise ------------------------------------------------------


def _raw_number(key: str, digits: int) -> bytes:
    """A conformant line whose ``key`` is a ``digits``-digit integer literal, built at
    the byte level because the standard library refuses to render such an integer."""
    line = _line()
    marker = f'"{key}":1,'.encode()
    assert marker in line
    return line.replace(marker, f'"{key}":'.encode() + b"9" * digits + b",", 1)


def _repeated(document: dict[str, Any], key: str, value: Any) -> bytes:
    inner = json.dumps(document, sort_keys=True, separators=(",", ":"))[1:-1]
    repeated = json.dumps({key: value}, separators=(",", ":"))[1:-1]
    return b"{" + repeated.encode("utf-8") + b"," + inner.encode("utf-8") + b"}\n"


@pytest.mark.parametrize(
    "line",
    [
        _repeated(_document(), "sequence", 2),
        _repeated(_document(), "attempt_token", _WRONG_TOKEN),
        _repeated(_document(), "invocation_id", OTHER_INVOCATION_ID),
        _repeated(_document(), "protocol_version", "2.0.0"),
        _line().replace(b'"payload":{', b'"payload":{"phase":"x",', 1),
        _encode(_document(invocation_id=chr(0xD800))),
        _encode(_document(attempt_token=chr(0xD800) * 32)),
        _encode(_document(event_type=chr(0xD800))),
        _encode(_document(payload={"activity_counter": 1, "phase": chr(0xDC00)})),
        _raw_number("sequence", 5000),
        _raw_number("activity_counter", 5000),
        _encode(_document(payload={"activity_counter": 1e400, "phase": "x"})),
        _line(payload={**_HEARTBEAT, ATTEMPT_TOKEN: 1}),
        _line(payload={"attempt_token": ATTEMPT_TOKEN, **_HEARTBEAT}),
        _line(timestamp_utc=ATTEMPT_TOKEN),
        _line(event_id=ATTEMPT_TOKEN),
        _line(run_id=ATTEMPT_TOKEN),
        b'{"invocation_id": "' + b"x" * 200_000 + b'"}\n',
        b'{"sequence": 1, "sequence": 1}\n',
        json.dumps(_document(), ensure_ascii=True).encode("utf-8") + b"\n",
    ],
    ids=[
        "repeated-sequence",
        "repeated-token",
        "repeated-invocation",
        "repeated-version",
        "repeated-nested-key",
        "surrogate-invocation",
        "surrogate-token",
        "surrogate-event-type",
        "surrogate-phase",
        "huge-sequence-digits",
        "huge-counter-digits",
        "float-overflow",
        "token-as-payload-key",
        "token-as-nested-attempt-token",
        "token-as-timestamp",
        "token-as-event-id",
        "token-as-run-id",
        "long-string",
        "repeated-scalar",
        "ascii-escaped",
    ],
)
def test_hostile_lines_are_rejected_or_accepted_but_never_raise_or_leak(
    line: bytes,
) -> None:
    outcome = _parse(line)
    dumped = outcome.model_dump_json()
    assert ATTEMPT_TOKEN not in dumped
    if isinstance(outcome, EventRejected):
        assert outcome.diagnostic.error_code in _CODES
    else:
        assert isinstance(outcome, EventAccepted)


def test_a_repeated_key_is_malformed_and_never_reaches_the_header() -> None:
    assert _code(_parse(_repeated(_document(), "sequence", 2))) == (
        PROTOCOL_MALFORMED_JSONL
    )
    assert _code(_parse(_repeated(_document(), "attempt_token", _WRONG_TOKEN))) == (
        PROTOCOL_MALFORMED_JSONL
    )
    # Control: reordered keys are one object.
    reordered = (
        json.dumps(
            dict(reversed(list(_document().items()))), separators=(",", ":")
        ).encode("utf-8")
        + b"\n"
    )
    assert isinstance(_parse(reordered), EventAccepted)


def test_a_lone_surrogate_reads_as_missing_identity_or_as_malformed() -> None:
    assert _code(_parse(_encode(_document(invocation_id=chr(0xD800))))) == (
        PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    )
    assert _code(_parse(_encode(_document(attempt_token=chr(0xD800) * 32)))) == (
        PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    )
    assert (
        _code(
            _parse(
                _encode(
                    _document(payload={"activity_counter": 1, "phase": chr(0xDC00)})
                )
            )
        )
        == PROTOCOL_MALFORMED_JSONL
    )


# --- The rejection record ------------------------------------------------------------


def test_a_rejection_carries_a_stage_six_diagnostic_and_a_sample_without_a_token() -> (
    None
):
    line = b"starting engine " + ATTEMPT_TOKEN.encode() + b"\n"
    clock = CountingClock(_RECEIVED)
    outcome = _parse(line, clock=clock)
    assert clock.reads == 1
    assert isinstance(outcome, EventRejected)
    assert outcome.outcome == "REJECTED"
    diagnostic = outcome.diagnostic
    assert diagnostic.error_code == PROTOCOL_STDOUT_CONTAMINATION
    assert diagnostic.category is DiagnosticCategory.PROTOCOL
    assert diagnostic.severity is DiagnosticSeverity.ERROR
    assert diagnostic.retriable is False
    assert diagnostic.invocation_id == INVOCATION_ID
    assert _missing(diagnostic.run_id)
    assert _missing(diagnostic.experiment_id)
    assert diagnostic.timestamp_utc == _RECEIVED
    assert diagnostic.source_component == "adapters.events"
    assert diagnostic.details == {
        "byte_length": len(line) - 1,
        "source_hash": sha256_bytes(line[:-1]),
    }
    assert diagnostic.causal_diagnostic_ids == ()
    assert ATTEMPT_TOKEN not in outcome.model_dump_json()
    assert ATTEMPT_TOKEN not in diagnostic.message
    assert outcome.sample.byte_length == len(line) - 1
    assert _missing(outcome.sample.sample)
    # Content-derived identity: the same line at another instant is the same id.
    again = _parse(line, clock=FixedClock(_RECEIVED + timedelta(days=1)))
    assert isinstance(again, EventRejected)
    assert again.diagnostic.diagnostic_id == diagnostic.diagnostic_id
    assert again.diagnostic.timestamp_utc != diagnostic.timestamp_utc
    assert EventRejected.model_validate(outcome.model_dump(mode="python")) == outcome
    with pytest.raises(ValidationError, match="frozen"):
        outcome.outcome = "ACCEPTED"  # type: ignore[assignment]


def test_the_parser_local_rejecter_never_prints_the_line_bytes() -> None:
    """Independent-review hardening: the rejecter holds the raw line for the sample
    facts, so its repr must not echo those bytes (a token may be among them)."""
    rejecter = _Rejecter(
        body=b"starting engine " + ATTEMPT_TOKEN.encode(),
        invocation_id=INVOCATION_ID,
        received_at_utc=_RECEIVED,
    )
    text = repr(rejecter)
    assert ATTEMPT_TOKEN not in text
    assert "starting engine" not in text
    assert INVOCATION_ID in text


def test_the_line_outcome_is_a_closed_discriminated_union() -> None:
    adapter: TypeAdapter[Any] = TypeAdapter(LineOutcome)
    accepted = _parse(_line())
    assert adapter.validate_python(accepted.model_dump(mode="python")) == accepted
    rejected = _parse(b"noise\n")
    assert adapter.validate_python(rejected.model_dump(mode="python")) == rejected
    with pytest.raises(ValidationError, match="outcome"):
        adapter.validate_python({"outcome": "PENDING"})
    with pytest.raises(ValidationError, match="redactions"):
        EventAccepted.model_validate(
            {**accepted.model_dump(mode="python"), "redactions": -1}
        )
    with pytest.raises(ValidationError, match="extra"):
        EventReplayed.model_validate(
            {"outcome": "REPLAYED", "event": _accepted(accepted), "redactions": 0}
        )


# --- The acceptance context -----------------------------------------------------------


def test_the_acceptance_context_admits_only_a_running_validate_or_run_invocation() -> (
    None
):
    good = _acceptance()
    assert dataclasses.is_dataclass(good)
    with pytest.raises(dataclasses.FrozenInstanceError):
        good.max_event_bytes = 1  # type: ignore[misc]
    assert "clock" not in repr(good)
    for state in CommandInvocationState:
        if state is CommandInvocationState.RUNNING:
            continue
        with pytest.raises(ValueError, match="RUNNING"):
            EventAcceptanceContext(
                invocation=sample_invocation(state, kind=CommandKind.RUN),
                attempt_token_hash=attempt_token_hash(ATTEMPT_TOKEN),
                max_event_bytes=MAX_EVENT_LINE_BYTES,
                ledger=InvocationEventLedger(),
                clock=FixedClock(_RECEIVED),
            )
    with pytest.raises(ValueError, match="VALIDATE or RUN"):
        EventAcceptanceContext(
            invocation=sample_invocation(
                CommandInvocationState.RUNNING, kind=CommandKind.DESCRIBE
            ),
            attempt_token_hash=attempt_token_hash(ATTEMPT_TOKEN),
            max_event_bytes=MAX_EVENT_LINE_BYTES,
            ledger=InvocationEventLedger(),
            clock=FixedClock(_RECEIVED),
        )


def test_the_acceptance_context_checks_its_hash_limit_ledger_and_clock() -> None:
    def build(**updates: Any) -> EventAcceptanceContext:
        kwargs: dict[str, Any] = {
            "invocation": sample_invocation(CommandInvocationState.RUNNING),
            "attempt_token_hash": attempt_token_hash(ATTEMPT_TOKEN),
            "max_event_bytes": MAX_EVENT_LINE_BYTES,
            "ledger": InvocationEventLedger(),
            "clock": FixedClock(_RECEIVED),
        }
        kwargs.update(updates)
        return EventAcceptanceContext(**kwargs)

    with pytest.raises(ValueError, match="attempt_token_hash"):
        build(attempt_token_hash="A" * 64)
    with pytest.raises(TypeError, match="attempt_token_hash"):
        build(attempt_token_hash=None)
    with pytest.raises(ValueError, match="max_event_bytes"):
        build(max_event_bytes=0)
    with pytest.raises(ValueError, match="max_event_bytes"):
        build(max_event_bytes=MAX_EVENT_LINE_BYTES + 1)
    with pytest.raises(TypeError, match="max_event_bytes"):
        build(max_event_bytes=True)
    with pytest.raises(TypeError, match="ledger"):
        build(ledger=())
    with pytest.raises(TypeError, match="Clock"):
        build(clock=object())
    with pytest.raises(TypeError, match="invocation"):
        build(invocation=None)
    with pytest.raises(TypeError, match="bytes"):
        parse_protocol_line("text", acceptance=build())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="EventAcceptanceContext"):
        parse_protocol_line(_line(), acceptance=object())  # type: ignore[arg-type]


def test_a_ledger_of_another_invocation_is_refused_by_the_context() -> None:
    other = EventAcceptanceContext(
        invocation=sample_invocation(
            CommandInvocationState.RUNNING,
            invocation_id=OTHER_INVOCATION_ID,
            run_id=OTHER_RUN_ID,
        ),
        attempt_token_hash=attempt_token_hash(ATTEMPT_TOKEN),
        max_event_bytes=MAX_EVENT_LINE_BYTES,
        ledger=InvocationEventLedger(),
        clock=FixedClock(_RECEIVED),
    )
    outcome = parse_protocol_line(
        _line(invocation_id=OTHER_INVOCATION_ID, run_id=OTHER_RUN_ID), acceptance=other
    )
    assert isinstance(outcome, EventAccepted)
    foreign = InvocationEventLedger().accept(outcome)
    with pytest.raises(ValueError, match="invocation"):
        _acceptance(ledger=foreign)


def test_a_payload_whose_keys_collapse_under_redaction_is_malformed() -> None:
    """Preventive (began green): the redaction step refuses to drop a member, and the
    parser maps that refusal to a malformed line with the token absent."""
    payload = {
        **_HEARTBEAT,
        f"k{ATTEMPT_TOKEN}": 1,
        f"k{REDACTION_PLACEHOLDER}": 2,
    }
    outcome = _parse(_line(payload=payload))
    assert _code(outcome) == PROTOCOL_MALFORMED_JSONL
    assert ATTEMPT_TOKEN not in outcome.model_dump_json()


# --- Cross-check findings (RED D) -----------------------------------------------------


def _escaped_json_text(value: str) -> str:
    """``value`` spelled entirely with JSON backslash-u escapes."""
    return "".join(f"\\u{ord(character):04x}" for character in value)


def test_a_deeply_nested_payload_is_malformed_and_never_raises() -> None:
    """Cross-check finding: a payload nested past the interpreter's recursion limit
    decodes (the C decoder has its own counter) but a recursive redaction walk or a
    re-serialization would raise; the parser must classify it as malformed."""
    depth = 1500
    document = _document(payload={"phase": "x", "activity_counter": 1})
    prefix = json.dumps(document, sort_keys=True, separators=(",", ":"))[:-1]
    line = prefix.encode() + b',"nested":' + b"[" * depth + b"1" + b"]" * depth + b"}\n"
    outcome = _parse(line)
    assert _code(outcome) == PROTOCOL_MALFORMED_JSONL
    assert isinstance(outcome, EventRejected)
    assert ATTEMPT_TOKEN not in outcome.model_dump_json()
    # A deeply nested wrong-type header field is also malformed, not an exception.
    header_nested = (
        b'{"schema_version":"1.0.0","protocol_version":"1.0.0","invocation_id":'
        + b"[" * depth
        + b"]" * depth
        + b"}\n"
    )
    assert _code(_parse(header_nested)) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION


def test_a_json_escaped_token_cannot_reach_the_rejection_sample() -> None:
    """Cross-check finding: the header reader hashes the decoded token, so a token
    spelled with backslash-u escapes verifies, while the wire text carries no literal
    occurrence a text redaction could find. The sample must be derived from the
    redacted decoded object, never from the wire text."""
    document = _document(payload={"activity_counter": 1, "phase": "Phase"})
    text = json.dumps(document, sort_keys=True, separators=(",", ":"))
    escaped = text.replace(
        f'"{ATTEMPT_TOKEN}"', f'"{_escaped_json_text(ATTEMPT_TOKEN)}"'
    )
    assert ATTEMPT_TOKEN not in escaped
    line = escaped.encode("ascii") + b"\n"
    outcome = _parse(line)
    assert _code(outcome) == PROTOCOL_MALFORMED_JSONL
    assert isinstance(outcome, EventRejected)
    sample = outcome.sample.sample
    assert not _missing(sample)
    assert ATTEMPT_TOKEN not in sample
    assert "u0041" not in sample
    assert REDACTION_PLACEHOLDER in sample
    assert outcome.sample.byte_length == len(line) - 1
    assert outcome.sample.source_hash == sha256_bytes(line[:-1])
    # Control: the same escaped line with a conformant payload is accepted, and the
    # sanitized event carries the hash of the decoded token.
    accepted = _parse(escaped.replace('"Phase"', '"phase"').encode("ascii") + b"\n")
    assert isinstance(accepted, EventAccepted)
    assert accepted.event.attempt_token_hash == attempt_token_hash(ATTEMPT_TOKEN)


def test_a_boolean_sequence_is_a_missing_sequence() -> None:
    """Preventive (began green): ``bool`` subclasses ``int`` in Python, but a JSON
    ``true`` is not a sequence number; the header reads it as absent."""
    assert (
        _code(_parse(_line(sequence=True))) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    )
    assert (
        _code(_parse(_line(sequence=False))) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    )


@pytest.mark.parametrize(
    ("event_type", "payload"),
    [
        ("HEARTBEAT", {**_HEARTBEAT, "relative_path": "../x"}),
        ("ARTIFACT_PRODUCED", {**_ARTIFACT, "manifest_relative_path": "../x"}),
        (
            "DIAGNOSTIC",
            {
                "diagnostic": {
                    **_DIAGNOSTIC["diagnostic"],
                    "details": {"relative_path": 1.5},
                }
            },
        ),
        (
            "DIAGNOSTIC",
            {
                "diagnostic": {
                    **_DIAGNOSTIC["diagnostic"],
                    "details": {"outer": {"manifest_relative_path": "x" * 3000}},
                }
            },
        ),
    ],
    ids=[
        "extra-path-key",
        "extra-manifest-key",
        "detail-path-key",
        "nested-detail-key",
    ],
)
def test_a_path_named_key_outside_the_path_field_is_malformed(
    event_type: str, payload: dict[str, Any]
) -> None:
    """Preventive (began green): only an error at the payload class's own path field
    is a path violation; an unknown key or a detail key that merely bears the name
    is a schema failure."""
    assert _code(_parse(_encode(_typed(event_type, payload=payload)))) == (
        PROTOCOL_MALFORMED_JSONL
    )
