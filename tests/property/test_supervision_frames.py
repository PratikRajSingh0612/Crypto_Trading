"""Stage 7 Task 3: chunk boundaries never change what ``StdoutFramer`` frames.

Two properties of plan sections 6.7 and 7.1 (specification 14.4, 14.7). First, for a
recorded multi-line stdout stream whose units fit ``max_event_bytes``, any partition
of its bytes into chunks fed through ``StdoutFramer`` yields exactly the framed units
the unsplit stream yields, and the flush equals the unsplit carry-over -- the merged
``frame_protocol_lines`` guarantee transfers to the reader because the framer is the
same function. Second, an over-long unterminated tail is emitted early: after every
feed the carry-over never exceeds ``max_event_bytes``, every unterminated unit exceeds
it, and no byte is lost or reordered. ``deadline=None`` because the suite may run
under load.
"""

from __future__ import annotations

from itertools import pairwise
from typing import Final

from hypothesis import given, settings
from hypothesis import strategies as st

from crypto_lab.adapters.events import frame_protocol_lines
from crypto_lab.process_supervision.readers import StdoutFramer

_MAX_EVENT_BYTES: Final = 48
_UNIT_BODY: Final = st.binary(min_size=0, max_size=_MAX_EVENT_BYTES).filter(
    lambda body: b"\n" not in body
)
_LONG_BODY: Final = st.binary(
    min_size=_MAX_EVENT_BYTES + 1, max_size=4 * _MAX_EVENT_BYTES
).filter(lambda body: b"\n" not in body)


def _cuts(draw: st.DrawFn, whole: bytes) -> list[bytes]:
    cuts = sorted(
        draw(
            st.sets(
                st.integers(min_value=0, max_value=len(whole)), min_size=0, max_size=24
            )
        )
    )
    edges = [0, *cuts, len(whole)]
    return [whole[start:end] for start, end in pairwise(edges)]


@st.composite
def fitting_stream(draw: st.DrawFn) -> tuple[bytes, list[bytes]]:
    """A stream of terminated units within the bound, an optional short tail, and one
    arbitrary partition of its bytes into chunks."""
    bodies = draw(st.lists(_UNIT_BODY, min_size=0, max_size=12))
    tail = draw(_UNIT_BODY)
    whole = b"".join(body + b"\n" for body in bodies) + tail
    return whole, _cuts(draw, whole)


@st.composite
def stream_with_long_tail(draw: st.DrawFn) -> tuple[bytes, list[bytes]]:
    """Terminated units within the bound followed by an over-long unterminated tail."""
    bodies = draw(st.lists(_UNIT_BODY, min_size=0, max_size=6))
    tail = draw(_LONG_BODY)
    whole = b"".join(body + b"\n" for body in bodies) + tail
    return whole, _cuts(draw, whole)


def _frame_in_chunks(chunks: list[bytes]) -> tuple[list[bytes], bytes, int]:
    framer = StdoutFramer(max_event_bytes=_MAX_EVENT_BYTES)
    units: list[bytes] = []
    largest_carry = 0
    for chunk in chunks:
        units.extend(framer.feed(chunk))
        largest_carry = max(largest_carry, len(framer.pending_bytes))
    return units, framer.flush(), largest_carry


@settings(max_examples=120, deadline=None)
@given(example=fitting_stream())
def test_every_chunking_of_a_fitting_stream_frames_the_same_units(
    example: tuple[bytes, list[bytes]],
) -> None:
    whole, chunks = example
    assert b"".join(chunks) == whole
    expected_units, expected_carry = frame_protocol_lines(
        b"", whole, max_event_bytes=_MAX_EVENT_BYTES
    )
    units, carry, largest_carry = _frame_in_chunks(chunks)
    assert units == list(expected_units)
    assert carry == expected_carry
    assert largest_carry <= _MAX_EVENT_BYTES
    unsplit = StdoutFramer(max_event_bytes=_MAX_EVENT_BYTES)
    assert list(unsplit.feed(whole)) == units
    assert unsplit.flush() == carry


@settings(max_examples=120, deadline=None)
@given(example=stream_with_long_tail())
def test_an_over_long_tail_is_emitted_early_and_the_carry_over_stays_bounded(
    example: tuple[bytes, list[bytes]],
) -> None:
    whole, chunks = example
    units, carry, largest_carry = _frame_in_chunks(chunks)
    assert largest_carry <= _MAX_EVENT_BYTES
    assert len(carry) <= _MAX_EVENT_BYTES
    assert b"".join(units) + carry == whole  # no byte lost or reordered
    unterminated = [unit for unit in units if not unit.endswith(b"\n")]
    assert unterminated  # the tail was emitted before end of stream at least once
    assert all(len(unit) > _MAX_EVENT_BYTES for unit in unterminated)
    terminated = [unit for unit in units if unit.endswith(b"\n")]
    unsplit_units, _ = frame_protocol_lines(
        b"", whole, max_event_bytes=_MAX_EVENT_BYTES
    )
    assert terminated == [unit for unit in unsplit_units if unit.endswith(b"\n")]
