"""Stage 6 Task 4: the invocation event ledger, the summary and ``append_event``
(plan sections 7.2, 7.3, 7.5; specification 8.2, 14.4, 33.4).

The ledger is a pure fold over line outcomes: ``accept`` returns the successor,
``from_events`` rebuilds one from persisted events (so a restart cannot duplicate
an accepted event), ``summary`` projects it. The sequence rules that need ledger
state -- after ``FINAL_RESULT``, a second ``FINAL_RESULT``, a duplicate declared
path, a duplicate ``event_id``, a non-monotonic heartbeat counter, the kind
permission and the three collection bounds -- are driven through the parser here.
``EngineRunRepository.append_event`` and ``list_events`` are exercised on the
in-memory double: idempotent on an identical event, a conflict on a different
content under one key or a reused ``event_id``, ordered listing.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import UTC, datetime
from typing import Any, Final

import pytest
from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.diagnostics import (
    PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
    PROTOCOL_MALFORMED_JSONL,
)
from crypto_lab.adapters.events import (
    ArtifactDeclarationRecord,
    ArtifactProducedPayload,
    EventAcceptanceContext,
    EventAccepted,
    EventRejected,
    EventReplayed,
    FinalResultPayload,
    InvocationEventLedger,
    LineOutcome,
    ProtocolEventSummary,
    RunEvent,
    parse_protocol_line,
    run_event_content_hash,
)
from crypto_lab.adapters.limits import (
    MAX_ADAPTER_DIAGNOSTICS,
    MAX_CANDIDATE_ARTIFACTS,
    MAX_EVENT_LINE_BYTES,
    MAX_WARNINGS,
)
from crypto_lab.adapters.sanitization import REDACTION_PLACEHOLDER
from crypto_lab.domain.hashing import _uuid4_shaped, attempt_token_hash, sha256_bytes
from crypto_lab.domain.lifecycle import CommandInvocationState, CommandKind
from crypto_lab.domain.results import Failure, Success
from crypto_lab.experiments.diagnostics import CONCURRENCY_CONFLICT
from crypto_lab.experiments.ports import EngineRunRepository
from doubles.experiments import (
    ATTEMPT_TOKEN,
    INVOCATION_ID,
    OTHER_INVOCATION_ID,
    OTHER_RUN_ID,
    RUN_ID,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    sample_invocation,
)

_RECEIVED: Final = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)
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
    "declared_sha256": "a" * 64,
}
_FINAL: Final[dict[str, Any]] = {
    "manifest_relative_path": "adapter-result-manifest.json",
    "source_adapter_result_manifest_hash": "b" * 64,
    "semantic_status": "SUCCEEDED",
}


def _missing(value: object) -> bool:
    return value is MISSING


def _event_id(seed: object) -> str:
    return f"evt_{_uuid4_shaped(sha256_bytes(str(seed).encode('utf-8')))}"


def _document(
    sequence: int, event_type: str, payload: dict[str, Any], **updates: Any
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": "1.0.0",
        "protocol_version": "1.0.0",
        "event_id": _event_id(f"{INVOCATION_ID}:{sequence}"),
        "invocation_id": INVOCATION_ID,
        "run_id": RUN_ID,
        "attempt_token": ATTEMPT_TOKEN,
        "sequence": sequence,
        "event_type": event_type,
        "timestamp_utc": f"2026-09-11T10:00:{sequence % 60:02d}Z",
        "payload": payload,
    }
    document.update(updates)
    return document


def _encode(document: dict[str, Any]) -> bytes:
    text = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return text.encode("utf-8") + b"\n"


def _line(
    sequence: int, event_type: str, payload: dict[str, Any], **updates: Any
) -> bytes:
    return _encode(_document(sequence, event_type, payload, **updates))


def _acceptance(
    ledger: InvocationEventLedger,
    *,
    kind: CommandKind = CommandKind.RUN,
    clock: FixedClock | None = None,
) -> EventAcceptanceContext:
    return EventAcceptanceContext(
        invocation=sample_invocation(CommandInvocationState.RUNNING, kind=kind),
        attempt_token_hash=attempt_token_hash(ATTEMPT_TOKEN),
        max_event_bytes=MAX_EVENT_LINE_BYTES,
        ledger=ledger,
        clock=FixedClock(_RECEIVED) if clock is None else clock,
    )


def _feed(
    lines: list[bytes],
    *,
    kind: CommandKind = CommandKind.RUN,
    ledger: InvocationEventLedger | None = None,
) -> tuple[list[LineOutcome], InvocationEventLedger]:
    current = InvocationEventLedger() if ledger is None else ledger
    outcomes: list[LineOutcome] = []
    for line in lines:
        outcome = parse_protocol_line(line, acceptance=_acceptance(current, kind=kind))
        outcomes.append(outcome)
        current = current.accept(outcome)
    return outcomes, current


def _accepted(outcome: LineOutcome) -> RunEvent:
    assert isinstance(outcome, EventAccepted), outcome
    return outcome.event


def _code(outcome: LineOutcome) -> str:
    assert isinstance(outcome, EventRejected), outcome
    return outcome.diagnostic.error_code


def _same_id_at(event: RunEvent, event_id: str) -> RunEvent:
    """``event`` re-identified as ``event_id`` with its content hash recomputed."""
    draft = RunEvent.model_construct(**{**dict(event), "event_id": event_id})
    payload = draft.model_dump(mode="python")
    payload["content_hash"] = run_event_content_hash(draft)
    return RunEvent.model_validate(payload)


_RUN_STREAM: Final = [
    _line(1, "HEARTBEAT", _HEARTBEAT),
    _line(2, "PROGRESS", _PROGRESS),
    _line(3, "WARNING", _WARNING),
    _line(4, "DIAGNOSTIC", _DIAGNOSTIC),
    _line(5, "ARTIFACT_PRODUCED", _ARTIFACT),
    _line(6, "FINAL_RESULT", _FINAL),
]


# --- The fold ------------------------------------------------------------------------


def test_a_fresh_ledger_holds_nothing_and_summarises_to_zero() -> None:
    ledger = InvocationEventLedger()
    assert ledger.events == ()
    assert ledger.last_sequence == 0
    assert ledger.final_result_accepted is False
    assert ledger.redactions == 0
    summary = ledger.summary()
    assert summary == ProtocolEventSummary(
        accepted_count=0,
        last_sequence=0,
        artifact_declarations=(),
        warnings=(),
        adapter_diagnostics=(),
        redactions=0,
    )
    assert _missing(summary.final_result)
    assert dataclasses.is_dataclass(ledger)
    with pytest.raises(dataclasses.FrozenInstanceError):
        ledger.final_result_accepted = True  # type: ignore[misc]


def test_accept_appends_an_accepted_event_and_returns_the_same_ledger_otherwise() -> (
    None
):
    outcomes, ledger = _feed(_RUN_STREAM[:2])
    first, second = (_accepted(outcome) for outcome in outcomes)
    assert ledger.events == (first, second)
    assert ledger.last_sequence == 2
    assert ledger.event_ids == frozenset({first.event_id, second.event_id})
    replay = parse_protocol_line(_RUN_STREAM[0], acceptance=_acceptance(ledger))
    assert isinstance(replay, EventReplayed)
    assert ledger.accept(replay) is ledger
    rejected = parse_protocol_line(
        _line(9, "HEARTBEAT", _HEARTBEAT), acceptance=_acceptance(ledger)
    )
    assert isinstance(rejected, EventRejected)
    assert ledger.accept(rejected) is ledger


def _foreign_stream(count: int) -> list[EventAccepted]:
    """``count`` accepted events of another invocation, fed under its own context."""
    current = InvocationEventLedger()
    accepted: list[EventAccepted] = []
    for sequence in range(1, count + 1):
        outcome = parse_protocol_line(
            _line(
                sequence,
                "HEARTBEAT",
                {"activity_counter": sequence, "phase": "foreign"},
                invocation_id=OTHER_INVOCATION_ID,
                run_id=OTHER_RUN_ID,
                event_id=_event_id(f"{OTHER_INVOCATION_ID}:{sequence}"),
            ),
            acceptance=EventAcceptanceContext(
                invocation=sample_invocation(
                    CommandInvocationState.RUNNING,
                    invocation_id=OTHER_INVOCATION_ID,
                    run_id=OTHER_RUN_ID,
                ),
                attempt_token_hash=attempt_token_hash(ATTEMPT_TOKEN),
                max_event_bytes=MAX_EVENT_LINE_BYTES,
                ledger=current,
                clock=FixedClock(_RECEIVED),
            ),
        )
        assert isinstance(outcome, EventAccepted)
        accepted.append(outcome)
        current = current.accept(outcome)
    return accepted


def test_accept_refuses_a_non_successor_a_foreign_invocation_and_a_reused_id() -> None:
    outcomes, ledger = _feed(_RUN_STREAM[:2])
    first, second = outcomes
    assert isinstance(first, EventAccepted)
    assert isinstance(second, EventAccepted)
    one = InvocationEventLedger().accept(first)
    with pytest.raises(ValueError, match="sequence"):
        one.accept(first)
    with pytest.raises(ValueError, match="sequence"):
        InvocationEventLedger().accept(second)
    foreign_second = _foreign_stream(2)[1]
    assert foreign_second.event.sequence == 2
    with pytest.raises(ValueError, match="invocation"):
        one.accept(foreign_second)
    reused = EventAccepted(
        outcome="ACCEPTED",
        event=_same_id_at(second.event, first.event.event_id),
        redactions=0,
    )
    with pytest.raises(ValueError, match="event_id"):
        one.accept(reused)
    with pytest.raises(TypeError, match="LineOutcome"):
        one.accept(first.event)  # type: ignore[arg-type]
    assert ledger.last_sequence == 2


def test_a_complete_run_stream_is_summarised_exactly() -> None:
    outcomes, ledger = _feed(_RUN_STREAM)
    events = [_accepted(outcome) for outcome in outcomes]
    assert ledger.last_sequence == 6
    assert ledger.final_result_accepted is True
    assert ledger.artifact_paths == frozenset({"results/native.bin"})
    assert ledger.warning_count == 1
    assert ledger.diagnostic_count == 1
    assert ledger.last_heartbeat_counter == 1
    summary = ledger.summary()
    assert summary.accepted_count == 6
    assert summary.last_sequence == 6
    assert summary.artifact_declarations == (
        ArtifactDeclarationRecord(
            event_id=events[4].event_id,
            payload=ArtifactProducedPayload.model_validate_json(json.dumps(_ARTIFACT)),
        ),
    )
    assert len(summary.warnings) == 1
    assert summary.warnings[0].warning_code == "ADAPTER.APPROXIMATED_FILLS"
    assert summary.final_result == FinalResultPayload.model_validate_json(
        json.dumps(_FINAL)
    )
    assert len(summary.adapter_diagnostics) == 1
    assert summary.adapter_diagnostics[0].error_code == "ENGINE.DATA_GAP"
    assert summary.redactions == 0
    assert ProtocolEventSummary.model_validate(summary.model_dump(mode="python")) == (
        summary
    )


def test_redactions_are_summed_live_and_excluded_from_ledger_equality() -> None:
    tokened = dict(_WARNING)
    tokened["warning"] = {
        **_WARNING["warning"],
        "message": f"engine said {ATTEMPT_TOKEN} twice {ATTEMPT_TOKEN}",
    }
    outcomes, ledger = _feed([_RUN_STREAM[0], _line(2, "WARNING", tokened)])
    warning = outcomes[1]
    assert isinstance(warning, EventAccepted)
    assert warning.redactions == 2
    assert ATTEMPT_TOKEN not in warning.event.model_dump_json()
    assert REDACTION_PLACEHOLDER in warning.event.model_dump_json()
    assert ledger.redactions == 2
    assert ledger.summary().redactions == 2
    rebuilt = InvocationEventLedger.from_events(ledger.events)
    assert rebuilt.redactions == 0
    assert rebuilt == ledger
    assert dataclasses.replace(ledger, redactions=0) == ledger


def test_from_events_rebuilds_an_equal_ledger_that_replays_and_continues() -> None:
    outcomes, live = _feed(_RUN_STREAM[:5])
    rebuilt = InvocationEventLedger.from_events(live.events)
    assert rebuilt == live
    assert rebuilt.events == live.events
    assert rebuilt.event_ids == live.event_ids
    assert rebuilt.artifact_paths == live.artifact_paths
    assert rebuilt.last_heartbeat_counter == live.last_heartbeat_counter
    assert (rebuilt.warning_count, rebuilt.diagnostic_count) == (1, 1)
    assert rebuilt.final_result_accepted is False
    # Restart cannot duplicate: every earlier line replays, a new line continues.
    replays, after = _feed(_RUN_STREAM[:5], ledger=rebuilt)
    assert all(isinstance(outcome, EventReplayed) for outcome in replays)
    assert [outcome.event for outcome in replays] == [  # type: ignore[union-attr]
        _accepted(outcome) for outcome in outcomes
    ]
    assert after is rebuilt
    continued, done = _feed([_RUN_STREAM[5]], ledger=after)
    assert isinstance(continued[0], EventAccepted)
    assert done.final_result_accepted is True
    assert InvocationEventLedger.from_events(()) == InvocationEventLedger()


def test_from_events_refuses_a_gap_disorder_mixed_invocation_or_reused_id() -> None:
    _, live = _feed(_RUN_STREAM[:3])
    first, second, third = live.events
    with pytest.raises(ValueError, match="sequence"):
        InvocationEventLedger.from_events((first, third))
    with pytest.raises(ValueError, match="sequence"):
        InvocationEventLedger.from_events((second, first))
    with pytest.raises(ValueError, match="sequence"):
        InvocationEventLedger.from_events((second,))
    with pytest.raises(ValueError, match="event_id"):
        InvocationEventLedger.from_events((first, _same_id_at(second, first.event_id)))
    foreign_second = _foreign_stream(2)[1].event
    assert foreign_second.sequence == 2
    with pytest.raises(ValueError, match="invocation"):
        InvocationEventLedger.from_events((first, foreign_second))
    with pytest.raises(TypeError, match="RunEvent"):
        InvocationEventLedger.from_events((first, "x"))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="tuple"):
        InvocationEventLedger.from_events([first])  # type: ignore[arg-type]


# --- Sequence rules that need ledger state (plan 7.2, 7.3) ---------------------------


def test_no_new_event_follows_final_result_but_an_identical_replay_does() -> None:
    outcomes, ledger = _feed(_RUN_STREAM)
    after = parse_protocol_line(
        _line(7, "HEARTBEAT", {"activity_counter": 2, "phase": "late"}),
        acceptance=_acceptance(ledger),
    )
    assert _code(after) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    replay = parse_protocol_line(_RUN_STREAM[0], acceptance=_acceptance(ledger))
    assert isinstance(replay, EventReplayed)
    assert replay.event == _accepted(outcomes[0])
    second_final = parse_protocol_line(
        _line(7, "FINAL_RESULT", _FINAL), acceptance=_acceptance(ledger)
    )
    assert _code(second_final) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION


def test_a_second_final_result_is_a_sequence_violation() -> None:
    _, ledger = _feed([_RUN_STREAM[0], _line(2, "FINAL_RESULT", _FINAL)])
    assert ledger.final_result_accepted is True
    rejected = parse_protocol_line(
        _line(3, "FINAL_RESULT", {**_FINAL, "semantic_status": "FAILED"}),
        acceptance=_acceptance(ledger),
    )
    assert _code(rejected) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    assert ledger.accept(rejected) is ledger


def test_a_duplicate_declared_path_is_a_sequence_violation_and_a_new_path_is_not() -> (
    None
):
    _, ledger = _feed([_RUN_STREAM[0], _line(2, "ARTIFACT_PRODUCED", _ARTIFACT)])
    duplicate = parse_protocol_line(
        _line(3, "ARTIFACT_PRODUCED", {**_ARTIFACT, "declared_sha256": "c" * 64}),
        acceptance=_acceptance(ledger),
    )
    assert _code(duplicate) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    other = parse_protocol_line(
        _line(3, "ARTIFACT_PRODUCED", {**_ARTIFACT, "relative_path": "results/b.bin"}),
        acceptance=_acceptance(ledger),
    )
    assert isinstance(other, EventAccepted)


def test_a_duplicate_event_id_at_a_new_sequence_is_a_sequence_violation() -> None:
    outcomes, ledger = _feed(_RUN_STREAM[:1])
    reused = parse_protocol_line(
        _line(2, "PROGRESS", _PROGRESS, event_id=_accepted(outcomes[0]).event_id),
        acceptance=_acceptance(ledger),
    )
    assert _code(reused) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION


def test_the_heartbeat_counter_is_non_decreasing_across_accepted_heartbeats() -> None:
    _, ledger = _feed(
        [
            _line(1, "HEARTBEAT", {"activity_counter": 5, "phase": "warmup"}),
            _line(2, "HEARTBEAT", {"activity_counter": 5, "phase": "warmup"}),
            _line(3, "HEARTBEAT", {"activity_counter": 7, "phase": "run"}),
        ]
    )
    assert ledger.last_heartbeat_counter == 7
    decreasing = parse_protocol_line(
        _line(4, "HEARTBEAT", {"activity_counter": 6, "phase": "run"}),
        acceptance=_acceptance(ledger),
    )
    assert _code(decreasing) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    equal = parse_protocol_line(
        _line(4, "HEARTBEAT", {"activity_counter": 7, "phase": "run"}),
        acceptance=_acceptance(ledger),
    )
    assert isinstance(equal, EventAccepted)


def test_two_heartbeats_replayed_out_of_counter_order_are_both_replays() -> None:
    lines = [
        _line(1, "HEARTBEAT", {"activity_counter": 1, "phase": "a"}),
        _line(2, "HEARTBEAT", {"activity_counter": 9, "phase": "a"}),
    ]
    _, ledger = _feed(lines)
    replays, after = _feed(list(reversed(lines)), ledger=ledger)
    assert all(isinstance(outcome, EventReplayed) for outcome in replays)
    assert after == ledger


@pytest.mark.parametrize("event_type", ["ARTIFACT_PRODUCED", "FINAL_RESULT"])
def test_run_only_events_during_validate_are_identity_violations(
    event_type: str,
) -> None:
    payload = _ARTIFACT if event_type == "ARTIFACT_PRODUCED" else _FINAL
    outcomes, ledger = _feed([_RUN_STREAM[0]], kind=CommandKind.VALIDATE)
    assert isinstance(outcomes[0], EventAccepted)
    rejected = parse_protocol_line(
        _line(2, event_type, payload),
        acceptance=_acceptance(ledger, kind=CommandKind.VALIDATE),
    )
    assert _code(rejected) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    # Control: the four shared kinds are accepted during VALIDATE.
    accepted, _ = _feed(_RUN_STREAM[:4], kind=CommandKind.VALIDATE)
    assert all(isinstance(outcome, EventAccepted) for outcome in accepted)


def _many(event_type: str, payloads: list[dict[str, Any]]) -> list[bytes]:
    return [
        _line(index + 1, event_type, payload) for index, payload in enumerate(payloads)
    ]


def test_the_warning_bound_is_a_sequence_rule() -> None:
    lines = _many("WARNING", [_WARNING] * (MAX_WARNINGS + 1))
    outcomes, ledger = _feed(lines[:MAX_WARNINGS])
    assert all(isinstance(outcome, EventAccepted) for outcome in outcomes)
    assert ledger.warning_count == MAX_WARNINGS
    over = parse_protocol_line(lines[MAX_WARNINGS], acceptance=_acceptance(ledger))
    assert _code(over) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    assert len(ledger.summary().warnings) == MAX_WARNINGS


def test_the_diagnostic_bound_is_a_sequence_rule() -> None:
    lines = _many("DIAGNOSTIC", [_DIAGNOSTIC] * (MAX_ADAPTER_DIAGNOSTICS + 1))
    outcomes, ledger = _feed(lines[:MAX_ADAPTER_DIAGNOSTICS])
    assert all(isinstance(outcome, EventAccepted) for outcome in outcomes)
    over = parse_protocol_line(
        lines[MAX_ADAPTER_DIAGNOSTICS], acceptance=_acceptance(ledger)
    )
    assert _code(over) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    assert len(ledger.summary().adapter_diagnostics) == MAX_ADAPTER_DIAGNOSTICS


def test_the_declaration_bound_is_a_sequence_rule() -> None:
    payloads = [
        {**_ARTIFACT, "relative_path": f"results/part-{index:03d}.bin"}
        for index in range(MAX_CANDIDATE_ARTIFACTS + 1)
    ]
    lines = _many("ARTIFACT_PRODUCED", payloads)
    outcomes, ledger = _feed(lines[:MAX_CANDIDATE_ARTIFACTS])
    assert all(isinstance(outcome, EventAccepted) for outcome in outcomes)
    over = parse_protocol_line(
        lines[MAX_CANDIDATE_ARTIFACTS], acceptance=_acceptance(ledger)
    )
    assert _code(over) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    assert len(ledger.summary().artifact_declarations) == MAX_CANDIDATE_ARTIFACTS


def test_a_malformed_repeat_of_an_accepted_sequence_is_malformed_not_replayed() -> None:
    _, ledger = _feed(_RUN_STREAM[:2])
    malformed = parse_protocol_line(
        _line(1, "HEARTBEAT", {"activity_counter": -1, "phase": "warmup"}),
        acceptance=_acceptance(ledger),
    )
    assert _code(malformed) == PROTOCOL_MALFORMED_JSONL


# --- The summary model ----------------------------------------------------------------


def test_the_summary_restates_contiguity_uniqueness_and_bounds() -> None:
    _, ledger = _feed(_RUN_STREAM)
    summary = ledger.summary()
    payload = summary.model_dump(mode="python")
    with pytest.raises(ValidationError, match="last_sequence"):
        ProtocolEventSummary.model_validate({**payload, "last_sequence": 7})
    declaration = summary.artifact_declarations[0]
    with pytest.raises(ValidationError, match="relative_path"):
        ProtocolEventSummary.model_validate(
            {**payload, "artifact_declarations": (declaration, declaration)}
        )
    with pytest.raises(ValidationError, match="extra"):
        ProtocolEventSummary.model_validate({**payload, "replays": 0})
    with pytest.raises(ValidationError, match="redactions"):
        ProtocolEventSummary.model_validate({**payload, "redactions": -1})
    with pytest.raises(ValidationError, match="frozen"):
        summary.accepted_count = 0
    assert tuple(ProtocolEventSummary.model_fields) == (
        "accepted_count",
        "last_sequence",
        "artifact_declarations",
        "warnings",
        "final_result",
        "adapter_diagnostics",
        "redactions",
    )
    assert tuple(ArtifactDeclarationRecord.model_fields) == ("event_id", "payload")
    assert "schema_version" not in ProtocolEventSummary.model_fields


# --- append_event and list_events on the double (plan 7.5) ----------------------------


def _events(lines: list[bytes]) -> list[RunEvent]:
    outcomes, _ = _feed(lines)
    return [_accepted(outcome) for outcome in outcomes]


def test_the_port_declares_append_event_and_list_events() -> None:
    assert hasattr(EngineRunRepository, "append_event")
    assert hasattr(EngineRunRepository, "list_events")
    store = InMemoryBackingStore()
    transaction = InMemoryUnitOfWork(store).begin()
    assert isinstance(transaction.engine_runs, EngineRunRepository)
    transaction.rollback()


def test_append_event_inserts_lists_in_order_and_is_idempotent_on_identity() -> None:
    first, second = _events(_RUN_STREAM[:2])
    store = InMemoryBackingStore()
    root = InMemoryUnitOfWork(store)
    transaction = root.begin()
    assert transaction.engine_runs.append_event(second) == Success(
        outcome="SUCCESS", value=second
    )
    assert transaction.engine_runs.append_event(first) == Success(
        outcome="SUCCESS", value=first
    )
    again = transaction.engine_runs.append_event(first)
    assert isinstance(again, Success)
    assert again.value is first
    assert transaction.engine_runs.list_events(INVOCATION_ID) == Success(
        outcome="SUCCESS", value=(first, second)
    )
    assert transaction.engine_runs.list_events(OTHER_INVOCATION_ID) == Success(
        outcome="SUCCESS", value=()
    )
    assert store.committed_run_events() == ()
    assert isinstance(transaction.commit(), Success)
    assert store.committed_run_events() == (first, second)
    later = root.begin()
    replay = later.engine_runs.append_event(second)
    assert isinstance(replay, Success)
    assert replay.value == second
    assert later.engine_runs.list_events(INVOCATION_ID).value == (first, second)  # type: ignore[union-attr]
    later.rollback()
    assert store.committed_run_events() == (first, second)


def test_append_event_conflicts_on_a_different_content_under_one_key() -> None:
    (first,) = _events(_RUN_STREAM[:1])
    (other,) = _events([_line(1, "PROGRESS", _PROGRESS)])
    assert other.sequence == first.sequence
    assert other.content_hash != first.content_hash
    store = InMemoryBackingStore()
    root = InMemoryUnitOfWork(store)
    transaction = root.begin()
    assert isinstance(transaction.engine_runs.append_event(first), Success)
    assert isinstance(transaction.commit(), Success)
    transaction = root.begin()
    conflict = transaction.engine_runs.append_event(other)
    assert isinstance(conflict, Failure)
    assert conflict.diagnostics[0].error_code == CONCURRENCY_CONFLICT
    assert conflict.diagnostics[0].invocation_id == INVOCATION_ID
    assert ATTEMPT_TOKEN not in conflict.model_dump_json()
    assert transaction.engine_runs.list_events(INVOCATION_ID).value == (first,)  # type: ignore[union-attr]
    transaction.rollback()
    assert store.committed_run_events() == (first,)


def test_append_event_conflicts_on_an_event_id_reused_under_another_key() -> None:
    first, second = _events(_RUN_STREAM[:2])
    store = InMemoryBackingStore()
    root = InMemoryUnitOfWork(store)
    transaction = root.begin()
    assert isinstance(transaction.engine_runs.append_event(first), Success)
    # Same identity under a new key, staged in the same transaction.
    same_id = _same_id_at(second, first.event_id)
    conflict = transaction.engine_runs.append_event(same_id)
    assert isinstance(conflict, Failure)
    assert conflict.diagnostics[0].error_code == CONCURRENCY_CONFLICT
    assert isinstance(transaction.commit(), Success)
    # And under a live row from an earlier transaction.
    transaction = root.begin()
    conflict = transaction.engine_runs.append_event(same_id)
    assert isinstance(conflict, Failure)
    transaction.rollback()
    assert store.committed_run_events() == (first,)


def test_commit_rejects_two_transactions_that_collide_on_an_event_id() -> None:
    first, second = _events(_RUN_STREAM[:2])
    store = InMemoryBackingStore()
    root = InMemoryUnitOfWork(store)
    left = root.begin()
    right = root.begin()
    assert isinstance(left.engine_runs.append_event(first), Success)
    assert isinstance(
        right.engine_runs.append_event(_same_id_at(second, first.event_id)), Success
    )
    assert isinstance(left.commit(), Success)
    outcome = right.commit()
    assert isinstance(outcome, Failure)
    assert outcome.diagnostics[0].error_code == CONCURRENCY_CONFLICT
    assert store.committed_run_events() == (first,)


def test_rollback_discards_appended_events_and_commit_publishes_them_together() -> None:
    first, second = _events(_RUN_STREAM[:2])
    store = InMemoryBackingStore()
    root = InMemoryUnitOfWork(store)
    transaction = root.begin()
    assert isinstance(transaction.engine_runs.append_event(first), Success)
    transaction.rollback()
    assert store.committed_run_events() == ()
    transaction = root.begin()
    assert isinstance(transaction.engine_runs.append_event(first), Success)
    assert isinstance(transaction.engine_runs.append_event(second), Success)
    assert isinstance(transaction.commit(), Success)
    assert store.committed_run_events() == (first, second)
    assert root.begin().engine_runs.list_events(INVOCATION_ID).value == (  # type: ignore[union-attr]
        first,
        second,
    )


def test_append_event_checks_its_argument_type() -> None:
    transaction = InMemoryUnitOfWork(InMemoryBackingStore()).begin()
    with pytest.raises(TypeError, match="RunEvent"):
        transaction.engine_runs.append_event("event")  # type: ignore[arg-type]
    transaction.rollback()
