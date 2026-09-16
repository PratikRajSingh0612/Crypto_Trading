"""Bounded pipe readers, the timed queue wait and the stdout framer (plan section 6.7).

A ``PipeReader`` is a daemon thread that moves one binary pipe into a bounded queue in
``READ_CHUNK_BYTES`` reads. When the queue is full the put is retried every
``TICK_SECONDS`` and ``put_retries`` grows: the reader blocks, the pipe fills, the
child's write blocks -- bounded memory (at most ``capacity`` chunks in flight per pipe)
and never a dropped byte while the child lives. An empty read is end of stream and
enqueues the ``ReaderEnd.EOF`` marker; an ``OSError`` from a read that the owner's
``cancel_read`` interrupted enqueues the distinct ``ReaderEnd.CANCELLED`` marker, so
``drain`` reports the end while the supervisor can tell the two apart. The thread
records ``threading.get_native_id()`` as ``native_thread_id`` at start, which is what
``LaunchedProcess.cancel_read`` takes.

The reader owns neither the stream nor its closure: the supervisor creates both
readers over the launched process's pipes, alone sets their ``stop`` event after the
tree is verified dead or the post-termination wait expired, joins them with a bound,
cancels a blocked read through the port, and closes a pipe only after its reader has
ended (plan 8.4). The daemon flag is not the cleanup mechanism; the stop, join and
cancellation path is. ``drain`` and ``wait_for_chunk`` are the only two ways bytes
leave a queue -- the latter is the single timed wait, which is why ``queue`` is
confined to this module -- and ``StdoutFramer`` wraps the merged
``frame_protocol_lines`` so the reader adds no framing rule: complete units go to the
merged parser, an over-long unterminated tail is emitted early, and the end-of-stream
fragment is handed over by ``flush``. Nothing here decodes, interprets or retains a
byte, reads a clock, or closes a stream.
"""

from __future__ import annotations

import queue
import threading
from enum import StrEnum
from typing import IO, Final

from crypto_lab.adapters.events import frame_protocol_lines
from crypto_lab.process_supervision.models import (
    QUEUE_CAPACITY_CHUNKS,
    READ_CHUNK_BYTES,
    TICK_SECONDS,
)

__all__ = ["PipeReader", "ReaderEnd", "StdoutFramer", "drain", "wait_for_chunk"]

#: The fixed thread name, so a surviving reader is recognisable in a thread listing.
_THREAD_NAME: Final = "crypto-lab-pipe-reader"
_INFINITE_SECONDS: Final = frozenset({float("inf"), float("-inf")})


class ReaderEnd(StrEnum):
    """How a reader ended: end of stream, or a read the owner cancelled (plan 6.7)."""

    EOF = "EOF"
    CANCELLED = "CANCELLED"


class PipeReader(threading.Thread):
    """One pipe into one bounded queue, with backpressure and one end marker.

    Constructed and started by its owner; ``stop`` is the owner's event, checked
    before every read and inside the put retry loop, and a stopped reader ends
    without a marker (``ended_by`` stays ``None``). A read that returns anything but
    ``bytes`` is a producer defect and raises ``TypeError`` in the thread rather than
    being encoded or swallowed.
    """

    def __init__(
        self,
        stream: IO[bytes],
        *,
        capacity: int = QUEUE_CAPACITY_CHUNKS,
        stop: threading.Event,
    ) -> None:
        if not callable(getattr(stream, "read", None)):
            raise TypeError("a pipe reader takes a binary stream with a read method")
        if type(capacity) is not int:
            raise TypeError("capacity must be a built-in integer of chunks")
        if capacity < 1:
            raise ValueError("capacity must be a positive number of chunks")
        if not isinstance(stop, threading.Event):
            raise TypeError("stop must be a threading.Event")
        super().__init__(name=_THREAD_NAME, daemon=True)
        self._stream = stream
        # ``threading.Thread`` owns a private ``_stop`` method; the owner's event
        # therefore lives under its own name.
        self._stop_event = stop
        self.queue: queue.Queue[bytes | ReaderEnd] = queue.Queue(maxsize=capacity)
        self.native_thread_id: int | None = None
        self.put_retries = 0
        self.ended_by: ReaderEnd | None = None

    def run(self) -> None:
        self.native_thread_id = threading.get_native_id()
        while not self._stop_event.is_set():
            try:
                chunk = self._stream.read(READ_CHUNK_BYTES)
            except OSError:
                self._end(ReaderEnd.CANCELLED)
                return
            if type(chunk) is not bytes:
                raise TypeError("a pipe reader reads bytes; a text stream is refused")
            if not chunk:
                self._end(ReaderEnd.EOF)
                return
            if not self._put(chunk):
                return

    def _end(self, marker: ReaderEnd) -> None:
        self.ended_by = marker
        self._put(marker)

    def _put(self, item: bytes | ReaderEnd) -> bool:
        """Enqueue with the tick timeout until it succeeds or the owner stopped us."""
        while True:
            try:
                self.queue.put(item, timeout=TICK_SECONDS)
            except queue.Full:
                self.put_retries += 1
                if self._stop_event.is_set():
                    return False
            else:
                return True


def drain(source: queue.Queue[bytes | ReaderEnd]) -> tuple[list[bytes], bool]:
    """Take everything available without blocking; the flag: a marker was seen."""
    chunks: list[bytes] = []
    ended = False
    while True:
        try:
            item = source.get_nowait()
        except queue.Empty:
            return chunks, ended
        if isinstance(item, ReaderEnd):
            ended = True
        else:
            chunks.append(item)


def wait_for_chunk(
    source: queue.Queue[bytes | ReaderEnd], timeout_seconds: float
) -> bytes | ReaderEnd | None:
    """The one timed wait: the dequeued chunk or marker, or ``None`` when none arrived.

    The caller hands a returned chunk to the framer (or notes a returned marker)
    before its next ``drain``, so no byte is lost. ``timeout_seconds`` is a finite,
    non-negative number of seconds; the supervisor passes ``min(TICK_SECONDS,
    remaining)``.
    """
    if isinstance(timeout_seconds, bool) or not isinstance(
        timeout_seconds, int | float
    ):
        raise TypeError("timeout_seconds must be a number of seconds")
    if (
        timeout_seconds != timeout_seconds
        or timeout_seconds in _INFINITE_SECONDS
        or timeout_seconds < 0
    ):
        raise ValueError("timeout_seconds must be finite and never negative")
    try:
        return source.get(timeout=timeout_seconds)
    except queue.Empty:
        return None


class StdoutFramer:
    """The merged ``frame_protocol_lines`` with a carry-over, per stdout pipe.

    ``feed`` returns every complete unit (terminator kept; an over-long unterminated
    tail early); ``pending_bytes`` is the bounded carry-over; ``flush`` returns and
    clears it at end of stream so the caller can hand a non-empty fragment to the
    parser, which rejects it as contamination.
    """

    __slots__ = ("_max_event_bytes", "_pending_bytes")

    def __init__(self, *, max_event_bytes: int) -> None:
        frame_protocol_lines(b"", b"", max_event_bytes=max_event_bytes)  # validates
        self._max_event_bytes = max_event_bytes
        self._pending_bytes = b""

    @property
    def pending_bytes(self) -> bytes:
        return self._pending_bytes

    def feed(self, chunk: bytes) -> tuple[bytes, ...]:
        units, self._pending_bytes = frame_protocol_lines(
            self._pending_bytes, chunk, max_event_bytes=self._max_event_bytes
        )
        return units

    def flush(self) -> bytes:
        pending_bytes, self._pending_bytes = self._pending_bytes, b""
        return pending_bytes
