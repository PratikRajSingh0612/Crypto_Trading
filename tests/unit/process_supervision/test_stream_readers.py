"""Stage 7 Task 3: bounded pipe readers, the timed wait and the stdout framer (plan
6.7).

A ``PipeReader`` is a daemon thread owned by its caller: it moves one binary pipe
into a bounded queue in ``READ_CHUNK_BYTES`` reads, blocks (counting ``put_retries``)
while the queue is full -- the backpressure that makes the child's write block --
and ends with exactly one ``ReaderEnd`` marker: ``EOF`` for an empty read,
``CANCELLED`` for an ``OSError`` from a read that ``cancel_read`` interrupted. The
reader never closes its stream and never decodes, frames or interprets a byte.
``drain`` and ``wait_for_chunk`` are the only two ways bytes leave the queue, and
``StdoutFramer`` hands complete units to the merged parser through the merged
``frame_protocol_lines``. Every stream here is a deterministic fake ``IO[bytes]``;
no child process, no clock and no real sleep decides an assertion.
"""

from __future__ import annotations

import ast
import queue
import threading
import time
from collections.abc import Callable, Iterator
from enum import StrEnum
from pathlib import Path
from typing import IO, Final, cast

import pytest

from crypto_lab.adapters.events import frame_protocol_lines
from crypto_lab.adapters.limits import MAX_EVENT_LINE_BYTES
from crypto_lab.process_supervision import readers as readers_module
from crypto_lab.process_supervision.models import (
    QUEUE_CAPACITY_CHUNKS,
    READ_CHUNK_BYTES,
    TICK_SECONDS,
)
from crypto_lab.process_supervision.readers import (
    PipeReader,
    ReaderEnd,
    StdoutFramer,
    drain,
    wait_for_chunk,
)

_THREAD_NAME: Final = "crypto-lab-pipe-reader"
_WAIT_BOUND_SECONDS: Final = 10.0
_PAUSE: Final = threading.Event()  # never set: ``wait`` on it is a bounded pause
#: Plan 2.6: the import closure of ``readers.py``.
_PURE_ROOTS: Final = frozenset(
    {"__future__", "enum", "queue", "threading", "typing", "crypto_lab"}
)
_STAGE4_BARE_NAMES: Final = frozenset(
    {"buffer", "context", "note", "problem", "compose", "Loader"}
)
waiting = threading.Event()


# --------------------------------------------------------------------------
# Module-local helpers (plan Task 3 "Test helpers")
# --------------------------------------------------------------------------


def _wait_until(predicate: Callable[[], bool]) -> bool:
    """Poll ``predicate`` with a bounded pause; the predicate, not time, decides."""
    deadline = time.monotonic() + _WAIT_BOUND_SECONDS
    while not predicate():
        if time.monotonic() >= deadline:
            return False
        _PAUSE.wait(0.002)
    return True


class _SlowSink:
    """A fake ``IO[bytes]`` whose ``read`` hands one chunk per call, then ``b""``.

    ``delay_first_read_until`` holds the first read until the predicate is true;
    ``attach(reader)`` gives it the reader whose ``put_retries`` its
    ``blocked_at_least_once_after(n)`` waits on once ``n`` chunks were handed out.
    """

    def __init__(
        self,
        chunks: list[bytes],
        delay_first_read_until: Callable[[], bool] | None = None,
    ) -> None:
        self._chunks = list(chunks)
        self._delay = delay_first_read_until
        self._reader: PipeReader | None = None
        self.reads: list[int] = []
        self.handed = 0
        self.closed = False

    def attach(self, reader: PipeReader) -> None:
        self._reader = reader

    def read(self, size: int = -1) -> bytes:
        if not self.reads and self._delay is not None:
            assert _wait_until(self._delay)
        self.reads.append(size)
        if not self._chunks:
            return b""
        self.handed += 1
        return self._chunks.pop(0)

    def close(self) -> None:
        self.closed = True

    def blocked_at_least_once_after(self, count: int) -> bool:
        reader = self._reader
        assert reader is not None
        return _wait_until(lambda: self.handed >= count and reader.put_retries > 0)


class _FailingSink(_SlowSink):
    """Hands its chunks, then raises ``OSError`` from the next read (cancelled)."""

    def read(self, size: int = -1) -> bytes:
        if not self._chunks:
            self.reads.append(size)
            raise OSError(995, "The I/O operation has been aborted", None, 995)
        return super().read(size)


class _TextSink:
    """A text stream: ``read`` returns ``str``, which the reader must refuse."""

    def read(self, size: int = -1) -> str:
        return "text"


def _stream(sink: object) -> IO[bytes]:
    return cast("IO[bytes]", sink)


def _reader(sink: object, *, capacity: int = QUEUE_CAPACITY_CHUNKS) -> PipeReader:
    return PipeReader(_stream(sink), capacity=capacity, stop=threading.Event())


def drain_all(source: queue.Queue[bytes | ReaderEnd]) -> tuple[list[bytes], bool]:
    """``drain`` repeated until the reader ended (bounded by the wait bound)."""
    collected: list[bytes] = []
    ended = False
    deadline = time.monotonic() + _WAIT_BOUND_SECONDS
    while not ended and time.monotonic() < deadline:
        chunks, ended = drain(source)
        collected.extend(chunks)
        if not chunks and not ended:
            _PAUSE.wait(0.002)
    return collected, ended


def _join(reader: PipeReader) -> None:
    reader.join(_WAIT_BOUND_SECONDS)
    assert not reader.is_alive()


def _retries_grew_past(reader: PipeReader, floor: int) -> Callable[[], bool]:
    return lambda: reader.put_retries > floor


def _reader_threads() -> list[threading.Thread]:
    return [thread for thread in threading.enumerate() if thread.name == _THREAD_NAME]


@pytest.fixture(autouse=True)
def _no_reader_thread_survives() -> Iterator[None]:
    assert _reader_threads() == []
    yield
    assert _reader_threads() == [], "a Task 3 reader thread outlived its test"


def _module_source() -> str:
    source = readers_module.__file__
    assert source is not None
    return Path(source).read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# Plan Task 3 Step 1 (verbatim)
# --------------------------------------------------------------------------


def test_the_reader_applies_backpressure_and_ends_with_a_sentinel() -> None:
    source = _SlowSink(chunks=[b"a" * 70_000] * 70)  # a fake IO[bytes]
    reader = PipeReader(
        _stream(source), capacity=QUEUE_CAPACITY_CHUNKS, stop=threading.Event()
    )
    source.attach(reader)  # the sink watches this reader's put_retries
    reader.start()
    assert source.blocked_at_least_once_after(QUEUE_CAPACITY_CHUNKS)
    chunks, ended = drain_all(reader.queue)
    assert b"".join(chunks) == b"a" * 70_000 * 70  # PT018: the plan's `and` split
    assert ended
    _join(reader)


def test_a_chunk_delivered_during_the_timed_wait_is_returned_not_lost() -> None:
    waiting.clear()
    source = _SlowSink(
        chunks=[b'{"a":1}\n'], delay_first_read_until=lambda: waiting.is_set()
    )
    reader = PipeReader(
        _stream(source), capacity=QUEUE_CAPACITY_CHUNKS, stop=threading.Event()
    )
    reader.start()
    waiting.set()
    item = wait_for_chunk(
        reader.queue, 1.0
    )  # the chunk arrives while the wait is blocked
    assert item == b'{"a":1}\n'  # returned to the caller, never dropped
    # PT018: the plan's single `and` assertion, split with both clauses in order
    assert wait_for_chunk(reader.queue, 0.05) is ReaderEnd.EOF
    assert wait_for_chunk(reader.queue, 0.05) is None
    _join(reader)


# --------------------------------------------------------------------------
# ReaderEnd and the reader's surface
# --------------------------------------------------------------------------


def test_reader_end_has_exactly_the_two_markers() -> None:
    assert issubclass(ReaderEnd, StrEnum)
    assert [member.name for member in ReaderEnd] == ["EOF", "CANCELLED"]
    assert [member.value for member in ReaderEnd] == ["EOF", "CANCELLED"]
    assert len(set(ReaderEnd)) == 2
    assert str(ReaderEnd.CANCELLED) == "CANCELLED"  # the STDOUT_READER_STOPPED fact


def test_a_reader_is_a_daemon_thread_that_starts_only_when_told() -> None:
    source = _SlowSink(chunks=[b"one"])
    reader = _reader(source)
    assert isinstance(reader, threading.Thread)
    assert reader.daemon is True
    assert reader.name == _THREAD_NAME
    assert not reader.is_alive()
    assert source.reads == []  # nothing at construction
    assert reader.native_thread_id is None
    assert reader.put_retries == 0
    assert reader.ended_by is None
    assert reader.queue.maxsize == QUEUE_CAPACITY_CHUNKS
    assert reader.queue.empty()
    reader.start()
    _join(reader)
    assert source.closed is False  # the reader never closes a stream it does not own
    assert isinstance(reader.native_thread_id, int)
    assert reader.native_thread_id != threading.get_native_id()


def test_a_reader_reads_in_read_chunk_bytes_and_marks_eof_exactly_once() -> None:
    source = _SlowSink(chunks=[b"one", b"two", b"three"])
    reader = _reader(source)
    reader.start()
    _join(reader)
    assert source.reads == [READ_CHUNK_BYTES] * 4  # three chunks and the EOF read
    assert reader.ended_by is ReaderEnd.EOF
    assert reader.put_retries == 0
    items: list[bytes | ReaderEnd] = []
    while True:
        try:
            items.append(reader.queue.get_nowait())
        except queue.Empty:
            break
    assert items == [b"one", b"two", b"three", ReaderEnd.EOF]


def test_an_empty_stream_yields_only_the_eof_marker() -> None:
    reader = _reader(_SlowSink(chunks=[]))
    reader.start()
    _join(reader)
    assert drain(reader.queue) == ([], True)
    assert reader.ended_by is ReaderEnd.EOF


def test_an_os_error_from_a_cancelled_read_marks_cancelled_never_eof() -> None:
    source = _FailingSink(chunks=[b"partial"])
    reader = _reader(source)
    reader.start()
    _join(reader)
    chunks, ended = drain(reader.queue)
    assert (chunks, ended) == ([b"partial"], True)
    assert reader.ended_by is ReaderEnd.CANCELLED
    assert reader.queue.empty()  # the CANCELLED marker was the last item
    assert "aborted" not in repr(reader)  # no exception text is retained
    assert not any(isinstance(value, BaseException) for value in vars(reader).values())


def test_the_cancelled_marker_is_distinct_from_eof_in_the_queue() -> None:
    reader = _reader(_FailingSink(chunks=[]))
    reader.start()
    _join(reader)
    assert wait_for_chunk(reader.queue, 0.0) is ReaderEnd.CANCELLED
    assert wait_for_chunk(reader.queue, 0.0) is None


def test_stop_ends_a_reader_blocked_on_a_full_queue_without_a_marker() -> None:
    source = _SlowSink(chunks=[b"1", b"2", b"3"])
    stop = threading.Event()
    reader = PipeReader(_stream(source), capacity=1, stop=stop)
    source.attach(reader)
    reader.start()
    assert source.blocked_at_least_once_after(2)  # the second chunk cannot be put
    first_sample = reader.put_retries
    assert _wait_until(lambda: reader.put_retries > first_sample)  # one per timeout
    stop.set()
    _join(reader)
    assert drain(reader.queue) == ([b"1"], False)  # no marker: the owner stopped it
    assert reader.ended_by is None
    assert source.handed == 2
    assert len(source.reads) == 2


def test_a_stop_set_before_the_first_read_ends_the_reader_without_reading() -> None:
    source = _SlowSink(chunks=[b"never"])
    stop = threading.Event()
    stop.set()
    reader = PipeReader(_stream(source), capacity=4, stop=stop)
    reader.start()
    _join(reader)
    assert source.reads == []
    assert reader.queue.empty()
    assert reader.ended_by is None
    assert isinstance(reader.native_thread_id, int)  # recorded before the first check


def test_the_queue_holds_at_most_capacity_chunks_of_read_chunk_bytes() -> None:
    capacity = 3
    source = _SlowSink(chunks=[bytes([index]) * READ_CHUNK_BYTES for index in range(8)])
    reader = _reader(source, capacity=capacity)
    source.attach(reader)
    reader.start()
    assert source.blocked_at_least_once_after(capacity + 1)
    assert reader.queue.qsize() == capacity
    assert reader.queue.maxsize == capacity
    assert source.handed == capacity + 1  # one chunk is held by the blocked put
    chunks, ended = drain_all(reader.queue)
    assert len(chunks) == 8
    assert ended
    assert sum(len(chunk) for chunk in chunks) == 8 * READ_CHUNK_BYTES
    _join(reader)


def test_put_retries_count_every_full_timeout_while_nobody_drains() -> None:
    source = _SlowSink(chunks=[b"a", b"b"])
    stop = threading.Event()
    reader = PipeReader(_stream(source), capacity=1, stop=stop)
    source.attach(reader)
    reader.start()
    assert source.blocked_at_least_once_after(2)
    samples = [reader.put_retries]
    for _ in range(3):
        assert _wait_until(_retries_grew_past(reader, samples[-1]))
        samples.append(reader.put_retries)
    assert samples == sorted(samples)
    assert len(set(samples)) == 4
    stop.set()
    _join(reader)
    assert drain(reader.queue) == ([b"a"], False)


def test_the_reader_validates_its_arguments_and_the_default_capacity() -> None:
    stop = threading.Event()
    assert PipeReader(_stream(_SlowSink([])), stop=stop).queue.maxsize == (
        QUEUE_CAPACITY_CHUNKS
    )
    with pytest.raises(TypeError, match="read"):
        PipeReader(_stream(object()), stop=stop)
    with pytest.raises(ValueError, match="capacity"):
        PipeReader(_stream(_SlowSink([])), capacity=0, stop=stop)
    with pytest.raises(ValueError, match="capacity"):
        PipeReader(_stream(_SlowSink([])), capacity=-1, stop=stop)
    with pytest.raises(TypeError, match="capacity"):
        PipeReader(_stream(_SlowSink([])), capacity=True, stop=stop)
    with pytest.raises(TypeError, match="capacity"):
        PipeReader(
            _stream(_SlowSink([])),
            capacity="64",  # type: ignore[arg-type]
            stop=stop,
        )
    with pytest.raises(TypeError, match="stop"):
        PipeReader(
            _stream(_SlowSink([])),
            stop=object(),  # type: ignore[arg-type]
        )


def test_a_text_stream_is_refused_not_silently_encoded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raised: list[type[BaseException] | None] = []

    def record(arguments: threading.ExceptHookArgs) -> None:
        raised.append(arguments.exc_type)

    monkeypatch.setattr(threading, "excepthook", record)
    reader = _reader(_TextSink())
    reader.start()
    _join(reader)
    assert raised == [TypeError]  # not swallowed: the thread's exception hook saw it
    assert reader.queue.empty()  # no marker
    assert reader.ended_by is None  # and nothing was encoded


# --------------------------------------------------------------------------
# drain and wait_for_chunk
# --------------------------------------------------------------------------


def test_drain_takes_everything_available_and_reports_a_marker() -> None:
    source: queue.Queue[bytes | ReaderEnd] = queue.Queue()
    assert drain(source) == ([], False)
    source.put(b"a")
    source.put(b"b")
    assert drain(source) == ([b"a", b"b"], False)
    source.put(b"c")
    source.put(ReaderEnd.EOF)
    assert drain(source) == ([b"c"], True)
    assert drain(source) == ([], False)  # the marker is consumed once
    source.put(ReaderEnd.CANCELLED)
    assert drain(source) == ([], True)


def test_wait_for_chunk_returns_the_dequeued_item_or_none() -> None:
    source: queue.Queue[bytes | ReaderEnd] = queue.Queue()
    assert wait_for_chunk(source, 0.0) is None
    assert wait_for_chunk(source, TICK_SECONDS) is None
    source.put(b"a")
    source.put(ReaderEnd.EOF)
    assert wait_for_chunk(source, 0.0) == b"a"
    assert wait_for_chunk(source, 0.0) is ReaderEnd.EOF
    assert wait_for_chunk(source, 0) is None  # an int bound is a number of seconds
    for bad in (-0.001, -1, float("nan"), float("inf")):
        with pytest.raises(ValueError, match="timeout"):
            wait_for_chunk(source, bad)
    for wrong in (True, "0.02", None):
        with pytest.raises(TypeError, match="timeout"):
            wait_for_chunk(source, wrong)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# StdoutFramer
# --------------------------------------------------------------------------


def test_the_framer_yields_complete_units_and_flushes_the_carry_over() -> None:
    framer = StdoutFramer(max_event_bytes=64)
    assert framer.pending_bytes == b""
    assert framer.feed(b"a\nb") == (b"a\n",)
    assert framer.pending_bytes == b"b"
    assert framer.feed(b"c\n\nd") == (b"bc\n", b"\n")
    assert framer.pending_bytes == b"d"
    assert framer.feed(b"") == ()
    assert framer.feed(b"x\r\ny\n") == (b"dx\r\n", b"y\n")  # CRLF is left inside
    assert framer.pending_bytes == b""
    assert framer.feed(b"tail") == ()
    assert framer.flush() == b"tail"  # the EOF fragment for the parser
    assert framer.pending_bytes == b""
    assert framer.flush() == b""


def test_the_framer_emits_an_over_long_tail_early_and_bounds_its_carry_over() -> None:
    framer = StdoutFramer(max_event_bytes=8)
    assert framer.feed(b"z" * 5) == ()
    assert framer.feed(b"z" * 4) == (b"z" * 9,)  # emitted without a terminator
    assert framer.pending_bytes == b""
    assert framer.feed(b"z" * 8) == ()  # exactly the bound is carried
    assert len(framer.pending_bytes) == 8
    assert framer.feed(b"\nq") == (b"z" * 8 + b"\n",)
    assert framer.flush() == b"q"
    assert framer.feed(b"z" * 20) == (b"z" * 20,)


def test_the_framer_is_the_merged_framer_and_validates_the_bound_eagerly() -> None:
    whole = b'{"a":1}\n{"b":2}\nfrag'
    framer = StdoutFramer(max_event_bytes=MAX_EVENT_LINE_BYTES)
    units = [*framer.feed(whole[:5]), *framer.feed(whole[5:])]
    expected, remainder = frame_protocol_lines(
        b"", whole, max_event_bytes=MAX_EVENT_LINE_BYTES
    )
    assert tuple(units) == expected
    assert framer.flush() == remainder
    with pytest.raises(ValueError, match="max_event_bytes"):
        StdoutFramer(max_event_bytes=0)
    with pytest.raises(ValueError, match="max_event_bytes"):
        StdoutFramer(max_event_bytes=MAX_EVENT_LINE_BYTES + 1)
    with pytest.raises(TypeError, match="max_event_bytes"):
        StdoutFramer(max_event_bytes=True)
    with pytest.raises(TypeError, match="bytes"):
        StdoutFramer(max_event_bytes=64).feed("text")  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Purity: the reviewed import closure, `queue` confined here, the exported surface
# --------------------------------------------------------------------------


def _imported(tree: ast.Module) -> tuple[set[str], set[str]]:
    roots: set[str] = set()
    project: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.partition(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.partition(".")[0])
            if node.module.startswith("crypto_lab"):
                project.add(node.module)
    return roots, project


def test_the_module_imports_only_threading_queue_and_the_merged_framer() -> None:
    text = _module_source()
    tree = ast.parse(text)
    roots, project = _imported(tree)
    assert roots <= _PURE_ROOTS, roots - _PURE_ROOTS
    assert {"threading", "queue"} <= roots
    assert project == {
        "crypto_lab.adapters.events",
        "crypto_lab.process_supervision.models",
    }
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    assert names & _STAGE4_BARE_NAMES == set()
    for forbidden in (
        "import time",
        "import asyncio",
        "import subprocess",
        "import os",
        "import io",
        "sleep(",
        "datetime.now",
        "uuid4(",
        "import doubles",
        "from doubles",
        ".close(",
        ".decode(",
        "json",
    ):
        assert forbidden not in text, forbidden
    assert "from __future__ import annotations" in text


def test_queue_is_imported_by_no_other_source_module() -> None:
    source = readers_module.__file__
    assert source is not None
    package_root = Path(source).resolve().parents[1]  # src/crypto_lab
    importers: set[str] = set()
    for path in sorted(package_root.rglob("*.py")):
        roots, _ = _imported(ast.parse(path.read_text(encoding="utf-8")))
        if "queue" in roots:
            importers.add(path.relative_to(package_root).as_posix())
    assert importers == {"process_supervision/readers.py"}


def test_the_exported_surface_is_exactly_the_plan_inventory() -> None:
    assert list(readers_module.__all__) == [
        "PipeReader",
        "ReaderEnd",
        "StdoutFramer",
        "drain",
        "wait_for_chunk",
    ]
    public = {
        name
        for name, value in vars(readers_module).items()
        if not name.startswith("_")
        and getattr(value, "__module__", None) == readers_module.__name__
    }
    assert public == set(readers_module.__all__)
    assert set(vars(PipeReader)) >= {"run"}
    assert "queue" not in vars(PipeReader)  # the queue is per instance, never shared
