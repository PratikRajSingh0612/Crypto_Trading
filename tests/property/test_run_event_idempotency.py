"""Stage 6 Task 4: the sanitized event content identity and idempotent replay.

Properties over ``RUN_EVENT_CONTENT_V1`` (plan section 4; specification 10.2, 14.4):
``content_hash`` ignores the receipt instant and the exact wire bytes (an identical
line re-serialized with other whitespace or key order, received under an advanced
clock, is ``EventReplayed`` and ``append_event`` stores nothing new); it moves under
every material field; and ``append_event`` is idempotent on the identical event while a
different content under one key conflicts. ``deadline=None`` because every example
validates several strict models and the suite may run under load.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from crypto_lab.adapters.events import (
    EventAcceptanceContext,
    EventAccepted,
    EventReplayed,
    HeartbeatPayload,
    InvocationEventLedger,
    RunEvent,
    parse_protocol_line,
    run_event_content_hash,
)
from crypto_lab.adapters.limits import MAX_COUNTER, MAX_EVENT_LINE_BYTES
from crypto_lab.adapters.vocabulary import ProtocolEventType
from crypto_lab.domain.hashing import _uuid4_shaped, attempt_token_hash, sha256_bytes
from crypto_lab.domain.lifecycle import CommandInvocationState, CommandKind
from crypto_lab.domain.results import Failure, Success
from doubles.experiments import (
    ATTEMPT_TOKEN,
    INVOCATION_ID,
    RUN_ID,
    CountingClock,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    sample_invocation,
)

_RECEIVED: Final = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)
_PHASES: Final = st.from_regex(r"[a-z][a-z0-9]{0,11}", fullmatch=True)
#: ``codec="utf-8"`` admits only encodable characters, so no lone surrogate is drawn.
_MESSAGES: Final = st.text(
    alphabet=st.characters(codec="utf-8", exclude_characters='\\"'),
    min_size=1,
    max_size=48,
)
_HEX: Final = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)


def _event_id(seed: str) -> str:
    return f"evt_{_uuid4_shaped(sha256_bytes(seed.encode('utf-8')))}"


@st.composite
def payloads(draw: st.DrawFn) -> tuple[str, dict[str, Any]]:
    kind = draw(st.sampled_from(["HEARTBEAT", "PROGRESS", "WARNING"]))
    if kind == "HEARTBEAT":
        return kind, {
            "activity_counter": draw(st.integers(min_value=0, max_value=MAX_COUNTER)),
            "phase": draw(_PHASES),
        }
    if kind == "PROGRESS":
        done = draw(st.integers(min_value=0, max_value=10**9))
        return kind, {
            "phase": draw(_PHASES),
            "completed_units": done,
            "total_units": done + draw(st.integers(min_value=0, max_value=10**9)),
            "percentage": str(draw(st.integers(min_value=0, max_value=100))),
        }
    return kind, {
        "warning": {
            "warning_code": "ADAPTER."
            + draw(st.from_regex(r"[A-Z][A-Z0-9_]{0,15}", fullmatch=True)),
            "message": draw(_MESSAGES),
            "impact": draw(_MESSAGES),
            "prevented_comparison_levels": draw(
                st.sampled_from([[], ["LEVEL_1"], ["LEVEL_2", "LEVEL_3"]])
            ),
        }
    }


@st.composite
def documents(draw: st.DrawFn) -> dict[str, Any]:
    event_type, payload = draw(payloads())
    seconds = draw(st.integers(min_value=0, max_value=10**8))
    stamped = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
    return {
        "schema_version": "1.0.0",
        "protocol_version": "1.0.0",
        "event_id": _event_id(draw(st.text(min_size=1, max_size=8))),
        "invocation_id": INVOCATION_ID,
        "run_id": RUN_ID,
        "attempt_token": ATTEMPT_TOKEN,
        "sequence": 1,
        "event_type": event_type,
        "timestamp_utc": stamped.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "payload": payload,
    }


def _encode(document: dict[str, Any], *, indent: int | None, reverse: bool) -> bytes:
    ordered = dict(reversed(list(document.items()))) if reverse else document
    text = json.dumps(
        ordered,
        indent=indent,
        separators=(",", ":") if indent is None else (", ", ": "),
        ensure_ascii=False,
    )
    return text.replace("\n", " ").encode("utf-8") + b"\n"


def _acceptance(
    ledger: InvocationEventLedger, clock: FixedClock
) -> EventAcceptanceContext:
    return EventAcceptanceContext(
        invocation=sample_invocation(
            CommandInvocationState.RUNNING, kind=CommandKind.RUN
        ),
        attempt_token_hash=attempt_token_hash(ATTEMPT_TOKEN),
        max_event_bytes=MAX_EVENT_LINE_BYTES,
        ledger=ledger,
        clock=clock,
    )


def _accept(line: bytes, clock: FixedClock) -> EventAccepted:
    outcome = parse_protocol_line(
        line, acceptance=_acceptance(InvocationEventLedger(), clock)
    )
    assert isinstance(outcome, EventAccepted), outcome
    return outcome


@settings(max_examples=60, deadline=None)
@given(
    document=documents(),
    indent=st.sampled_from([None, 1, 4]),
    reverse=st.booleans(),
    advance=st.integers(min_value=1, max_value=10**6),
)
def test_a_reserialized_replay_under_an_advanced_clock_is_the_same_content(
    document: dict[str, Any], indent: int | None, reverse: bool, advance: int
) -> None:
    first_line = _encode(document, indent=None, reverse=False)
    second_line = _encode(document, indent=indent, reverse=reverse)
    clock = CountingClock(_RECEIVED)
    accepted = _accept(first_line, clock)
    assert clock.reads == 1
    ledger = InvocationEventLedger().accept(accepted)
    clock.advance(advance)
    replay = parse_protocol_line(second_line, acceptance=_acceptance(ledger, clock))
    assert clock.reads == 2
    assert isinstance(replay, EventReplayed), replay
    assert replay.event is accepted.event
    assert replay.event.received_at_utc == _RECEIVED
    assert run_event_content_hash(accepted.event) == accepted.event.content_hash
    # The same bytes under another instant: a distinct RunEvent with the same content.
    later = _accept(second_line, FixedClock(_RECEIVED + timedelta(seconds=advance)))
    assert later.event.content_hash == accepted.event.content_hash
    assert later.event.received_at_utc == _RECEIVED + timedelta(seconds=advance)
    if second_line != first_line:
        assert later.event.wire_event_hash != accepted.event.wire_event_hash
    assert later.event.model_dump(exclude={"received_at_utc", "wire_event_hash"}) == (
        accepted.event.model_dump(exclude={"received_at_utc", "wire_event_hash"})
    )


@st.composite
def material_mutation(draw: st.DrawFn) -> tuple[str, object]:
    field = draw(
        st.sampled_from(
            [
                "event_id",
                "invocation_id",
                "run_id",
                "attempt_token_hash",
                "sequence",
                "timestamp_utc",
                "payload",
            ]
        )
    )
    value: object
    if field == "event_id":
        value = _event_id("mutated:" + draw(st.text(min_size=1, max_size=8)))
    elif field == "invocation_id":
        value = f"inv_{_uuid4_shaped(draw(_HEX))}"
    elif field == "run_id":
        value = f"run_{_uuid4_shaped(draw(_HEX))}"
    elif field == "attempt_token_hash":
        value = draw(_HEX)
    elif field == "sequence":
        value = draw(st.integers(min_value=2, max_value=1000))
    elif field == "timestamp_utc":
        value = datetime(2027, 1, 1, tzinfo=UTC) + timedelta(
            seconds=draw(st.integers(min_value=0, max_value=10**6))
        )
    else:
        value = {
            "activity_counter": draw(st.integers(min_value=0, max_value=99)),
            "phase": "mutated" + draw(_PHASES),
        }
    return field, value


@settings(max_examples=80, deadline=None)
@given(document=documents(), mutation=material_mutation())
def test_every_material_field_moves_the_content_identity(
    document: dict[str, Any], mutation: tuple[str, object]
) -> None:
    accepted = _accept(
        _encode(document, indent=None, reverse=False), FixedClock(_RECEIVED)
    )
    event = accepted.event
    field, value = mutation
    if field == "payload":
        assert isinstance(value, dict)
        value = HeartbeatPayload.model_validate(value)
        changes: dict[str, object] = {
            "payload": value,
            "event_type": ProtocolEventType.HEARTBEAT,
        }
        if event.event_type is ProtocolEventType.HEARTBEAT and event.payload == value:
            return
    else:
        if getattr(event, field) == value:
            return
        changes = {field: value}
    draft = RunEvent.model_construct(**{**dict(event), **changes})
    moved = run_event_content_hash(draft)
    assert moved != event.content_hash
    payload = draft.model_dump(mode="python")
    payload["content_hash"] = moved
    rebuilt = RunEvent.model_validate(payload)
    assert rebuilt.content_hash == moved
    payload["content_hash"] = event.content_hash
    with pytest.raises(ValueError, match="content_hash") as captured:
        RunEvent.model_validate(payload)
    assert ATTEMPT_TOKEN not in str(captured.value)


@settings(max_examples=40, deadline=None)
@given(left=documents(), right=documents())
def test_append_event_is_idempotent_on_identity_and_conflicts_on_content(
    left: dict[str, Any], right: dict[str, Any]
) -> None:
    first = _accept(
        _encode(left, indent=None, reverse=False), FixedClock(_RECEIVED)
    ).event
    second = _accept(
        _encode(right, indent=None, reverse=False), FixedClock(_RECEIVED)
    ).event
    store = InMemoryBackingStore()
    root = InMemoryUnitOfWork(store)
    transaction = root.begin()
    assert transaction.engine_runs.append_event(first) == Success(
        outcome="SUCCESS", value=first
    )
    again = transaction.engine_runs.append_event(first)
    assert isinstance(again, Success)
    assert again.value is first
    other = transaction.engine_runs.append_event(second)
    if second.content_hash == first.content_hash:
        assert isinstance(other, Success)
        assert other.value is first
    else:
        assert isinstance(other, Failure)
    assert isinstance(transaction.commit(), Success)
    assert store.committed_run_events() == (first,)
