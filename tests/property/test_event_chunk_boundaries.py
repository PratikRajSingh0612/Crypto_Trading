"""Stage 6 Task 4: chunk boundaries never change what the protocol accepts.

Two properties of plan section 7.1 and 7.3 (specification 14.4, 14.7): any split of a
valid multi-line stdout byte string into chunks, framed by ``frame_protocol_lines`` and
fed line by line to ``parse_protocol_line``, yields exactly the accepted ``RunEvent``
tuple the unsplit stream yields; and two invocations whose streams interleave never
collide on ``(invocation_id, sequence)``, each ledger accepting its own lines in
order. ``deadline=None`` because every example validates several strict models and
the suite may run under load.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from itertools import pairwise
from typing import Any, Final

from hypothesis import given, settings
from hypothesis import strategies as st

from crypto_lab.adapters.events import (
    EventAcceptanceContext,
    EventAccepted,
    InvocationEventLedger,
    RunEvent,
    frame_protocol_lines,
    parse_protocol_line,
)
from crypto_lab.adapters.limits import MAX_EVENT_LINE_BYTES
from crypto_lab.domain.hashing import _uuid4_shaped, attempt_token_hash, sha256_bytes
from crypto_lab.domain.lifecycle import CommandInvocationState, CommandKind
from crypto_lab.domain.results import Success
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
_OTHER_TOKEN: Final = "B" * 32
_PHASES: Final = st.from_regex(r"[a-z][a-z0-9]{0,11}", fullmatch=True)


def _event_id(seed: str) -> str:
    return f"evt_{_uuid4_shaped(sha256_bytes(seed.encode('utf-8')))}"


def _line(
    sequence: int,
    payload: dict[str, Any],
    event_type: str,
    *,
    invocation_id: str = INVOCATION_ID,
    run_id: str = RUN_ID,
    token: str = ATTEMPT_TOKEN,
) -> bytes:
    document = {
        "schema_version": "1.0.0",
        "protocol_version": "1.0.0",
        "event_id": _event_id(f"{invocation_id}:{sequence}"),
        "invocation_id": invocation_id,
        "run_id": run_id,
        "attempt_token": token,
        "sequence": sequence,
        "event_type": event_type,
        "timestamp_utc": (
            f"2026-09-11T10:{sequence // 60 % 60:02d}:{sequence % 60:02d}Z"
        ),
        "payload": payload,
    }
    text = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return text.encode("utf-8") + b"\n"


@st.composite
def stream(
    draw: st.DrawFn, *, invocation_id: str, run_id: str, token: str
) -> list[bytes]:
    """A valid RUN stream: non-decreasing heartbeats and progress lines, then an
    optional artifact declaration and final result."""
    count = draw(st.integers(min_value=1, max_value=8))
    lines: list[bytes] = []
    counter = 0
    sequence = 0
    for _ in range(count):
        sequence += 1
        if draw(st.booleans()):
            counter += draw(st.integers(min_value=0, max_value=5))
            payload: dict[str, Any] = {
                "activity_counter": counter,
                "phase": draw(_PHASES),
            }
            event_type = "HEARTBEAT"
        else:
            done = draw(st.integers(min_value=0, max_value=1000))
            payload = {
                "phase": draw(_PHASES),
                "completed_units": done,
                "total_units": done + draw(st.integers(min_value=0, max_value=1000)),
            }
            event_type = "PROGRESS"
        lines.append(
            _line(
                sequence,
                payload,
                event_type,
                invocation_id=invocation_id,
                run_id=run_id,
                token=token,
            )
        )
    if draw(st.booleans()):
        sequence += 1
        lines.append(
            _line(
                sequence,
                {
                    "relative_path": "results/" + draw(_PHASES) + ".bin",
                    "artifact_kind": "engine.native",
                    "media_type": "application/octet-stream",
                    "declared_size_bytes": draw(
                        st.integers(min_value=0, max_value=10**6)
                    ),
                    "declared_sha256": "a" * 64,
                },
                "ARTIFACT_PRODUCED",
                invocation_id=invocation_id,
                run_id=run_id,
                token=token,
            )
        )
        sequence += 1
        lines.append(
            _line(
                sequence,
                {
                    "manifest_relative_path": "adapter-result-manifest.json",
                    "source_adapter_result_manifest_hash": "b" * 64,
                    "semantic_status": "SUCCEEDED",
                },
                "FINAL_RESULT",
                invocation_id=invocation_id,
                run_id=run_id,
                token=token,
            )
        )
    return lines


@st.composite
def chunked(draw: st.DrawFn) -> tuple[list[bytes], list[bytes]]:
    """A valid stream and one arbitrary partition of its bytes into chunks."""
    lines = draw(
        stream(invocation_id=INVOCATION_ID, run_id=RUN_ID, token=ATTEMPT_TOKEN)
    )
    whole = b"".join(lines)
    cuts = sorted(
        draw(
            st.sets(
                st.integers(min_value=0, max_value=len(whole)), min_size=0, max_size=24
            )
        )
    )
    edges = [0, *cuts, len(whole)]
    chunks = [whole[start:end] for start, end in pairwise(edges)]
    return lines, chunks


def _acceptance(
    ledger: InvocationEventLedger,
    *,
    invocation_id: str = INVOCATION_ID,
    run_id: str = RUN_ID,
    token: str = ATTEMPT_TOKEN,
) -> EventAcceptanceContext:
    return EventAcceptanceContext(
        invocation=sample_invocation(
            CommandInvocationState.RUNNING,
            kind=CommandKind.RUN,
            invocation_id=invocation_id,
            run_id=run_id,
        ),
        attempt_token_hash=attempt_token_hash(token),
        max_event_bytes=MAX_EVENT_LINE_BYTES,
        ledger=ledger,
        clock=FixedClock(_RECEIVED),
    )


def _accept_all(lines: list[bytes], **identity: str) -> tuple[RunEvent, ...]:
    ledger = InvocationEventLedger()
    for line in lines:
        outcome = parse_protocol_line(line, acceptance=_acceptance(ledger, **identity))
        assert isinstance(outcome, EventAccepted), outcome
        ledger = ledger.accept(outcome)
    return ledger.events


@settings(max_examples=60, deadline=None)
@given(example=chunked())
def test_every_chunking_of_a_valid_stream_yields_the_same_accepted_events(
    example: tuple[list[bytes], list[bytes]],
) -> None:
    lines, chunks = example
    expected = _accept_all(lines)
    assert len(expected) == len(lines)
    framed: list[bytes] = []
    pending_bytes = b""
    for chunk in chunks:
        complete, pending_bytes = frame_protocol_lines(
            pending_bytes, chunk, max_event_bytes=MAX_EVENT_LINE_BYTES
        )
        framed.extend(complete)
    assert pending_bytes == b""
    assert framed == lines
    assert _accept_all(framed) == expected


@settings(max_examples=40, deadline=None)
@given(
    left=stream(invocation_id=INVOCATION_ID, run_id=RUN_ID, token=ATTEMPT_TOKEN),
    right=stream(
        invocation_id=OTHER_INVOCATION_ID, run_id=OTHER_RUN_ID, token=_OTHER_TOKEN
    ),
    order=st.lists(st.booleans(), min_size=32, max_size=32),
)
def test_interleaved_streams_of_two_invocations_never_collide(
    left: list[bytes], right: list[bytes], order: list[bool]
) -> None:
    ledgers = {
        INVOCATION_ID: InvocationEventLedger(),
        OTHER_INVOCATION_ID: InvocationEventLedger(),
    }
    identities = {
        INVOCATION_ID: {"run_id": RUN_ID, "token": ATTEMPT_TOKEN},
        OTHER_INVOCATION_ID: {"run_id": OTHER_RUN_ID, "token": _OTHER_TOKEN},
    }
    queues = {INVOCATION_ID: list(left), OTHER_INVOCATION_ID: list(right)}
    choices = iter(order)
    while queues[INVOCATION_ID] or queues[OTHER_INVOCATION_ID]:
        owner = INVOCATION_ID if next(choices, True) else OTHER_INVOCATION_ID
        if not queues[owner]:
            owner = OTHER_INVOCATION_ID if owner == INVOCATION_ID else INVOCATION_ID
        line = queues[owner].pop(0)
        outcome = parse_protocol_line(
            line,
            acceptance=_acceptance(
                ledgers[owner], invocation_id=owner, **identities[owner]
            ),
        )
        assert isinstance(outcome, EventAccepted), outcome
        ledgers[owner] = ledgers[owner].accept(outcome)
    events = [*ledgers[INVOCATION_ID].events, *ledgers[OTHER_INVOCATION_ID].events]
    keys = {(event.invocation_id, event.sequence) for event in events}
    assert len(keys) == len(events) == len(left) + len(right)
    assert [event.sequence for event in ledgers[INVOCATION_ID].events] == list(
        range(1, len(left) + 1)
    )
    assert [event.sequence for event in ledgers[OTHER_INVOCATION_ID].events] == list(
        range(1, len(right) + 1)
    )
    store = InMemoryBackingStore()
    transaction = InMemoryUnitOfWork(store).begin()
    for event in events:
        assert isinstance(transaction.engine_runs.append_event(event), Success)
    assert isinstance(transaction.commit(), Success)
    assert len(store.committed_run_events()) == len(events)
