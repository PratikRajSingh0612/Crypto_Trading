"""The section 5.2 container ``normalized-ndjson/0.1.0`` and the raw checksum.

One canonical JSON object per accepted row, in input order, duplicates
included: the keys ``close``, ``high``, ``low``, ``open``, ``open_time_utc``
and ``volume`` in that order (the core's sorted-key canonical JSON), the five
numbers as ``format_decimal`` strings, the open time as the core UTC string
form, compact separators, UTF-8, each line ended by ``\\n`` and the file
therefore ending with a final newline. ``normalized_checksum`` and
``content_hash`` are both the SHA-256 of the whole container's bytes and
``row_count`` is the number of lines written, so an independent line count
agrees with the metadata.

This is the interim container of plan boundary P2-B1: it is not the
production partition format and nothing here names it as such. The writer is
the one place in the package that writes. It writes exactly one file, the
caller's explicit destination, through one exclusive create (``"xb"``), and
returns ``Success[NormalizedContainer]`` or the whole-input refusal
``OFFLINE_DATA.OUTPUT_DIRECTORY`` (line ``0``, value length ``0``, the path
never recorded). Before it opens anything it inspects, without following
either, the destination's directory and then the destination's own entry: a
directory that is itself a reparse point is refused on its own attributes, as
the reader refuses its input, while a regular directory reached through a
junction in an ancestor is not a reparse point and is used; any existing
entry at the destination (a file, a directory, or a reparse point whether or
not its target exists) is refused before the create could follow it, so a
dangling link's missing target is never created, inside or outside the
output directory, and only the platform's "no such entry" answer lets the
create proceed. An existing entry is never overwritten, followed or removed,
and no directory is created, so the caller must provide an existing, writable
directory (the command of Task 3 creates its ``--output`` immediately before
this write). The writer owns the destination only once the exclusive create
has returned: a failure before that leaves nothing to remove; a failure of
the write, or of the close that completes it, removes the partial file it
created before anything else happens, and a removal that itself fails still
yields the same refusal. Every ``OSError`` of those scoped operations, and the
``ValueError`` a path the platform rejects outright raises (an embedded NUL,
which ``lstat`` and ``open`` refuse with ``ValueError`` rather than
``OSError``), is converted here; no provider is drawn inside those handlers,
so ``ProviderContractError`` (reading R7) is the only exception that crosses
this boundary and no provider is drawn on the accepting path.

``raw_checksum`` is the pipeline's one deliberate second read of the input:
the reader's single bounded read yields rows, not bytes, and the raw text's
exact digits survive only through this digest. It reuses the reader's
bounded-read helper by import, so a missing, unreadable, directory or
reparse-point input, a failing read and a rejected path are the reader's
``OFFLINE_DATA.INPUT_PATH`` refusal, a negative ceiling and an input over the
ceiling are its ``OFFLINE_DATA.SIZE_CEILING`` refusal with the reader's value
lengths, and the digest covers exactly the bytes read. The ceiling is a
required argument: the caller passes the ``max_bytes`` it gave the reader, so
the two reads of one input are bounded alike by construction rather than by
a second default.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.results import Failure, Success

from crypto_lab_offline_data.candle_csv import (
    _FILE_ATTRIBUTE_REPARSE_POINT,
    WHOLE_INPUT_LINE,
    CandleRow,
    _read_bounded,
)
from crypto_lab_offline_data.diagnostics import RefusalCode, refusal
from crypto_lab_offline_data.providers import Clock, IdProvider
from crypto_lab_offline_data.validation import ValidatedSeries

#: The ``column_schema_version`` of the normalized row schema (section 5.2).
COLUMN_SCHEMA_VERSION = "0.1.0"
#: The label of the interim container (reading R3, boundary P2-B1).
CONTAINER_FORMAT = "normalized-ndjson/0.1.0"
LINE_TERMINATOR = b"\n"


@dataclass(frozen=True, slots=True)
class NormalizedContainer:
    """What one container write produced: its size, identity and row count."""

    bytes_written: int
    content_hash: str
    normalized_checksum: str
    row_count: int


@dataclass(frozen=True, slots=True)
class RawChecksum:
    """The SHA-256 hex digest of the raw input bytes and how many there were."""

    sha256: str
    byte_count: int


type WriteResult = Success[NormalizedContainer] | Failure
type RawChecksumResult = Success[RawChecksum] | Failure


def normalized_row_bytes(row: CandleRow) -> bytes:
    """The one canonical JSON line of ``row``, terminated by ``\\n``."""
    record = {
        "open_time_utc": row.open_time_utc,
        "open": row.open,
        "high": row.high,
        "low": row.low,
        "close": row.close,
        "volume": row.volume,
    }
    return canonical_json_bytes(record) + LINE_TERMINATOR


def normalized_container_bytes(series: ValidatedSeries) -> bytes:
    """The whole container: every row's line in order, duplicates included."""
    return b"".join(normalized_row_bytes(row) for row in series.rows)


def write_normalized_container(
    series: ValidatedSeries,
    path: Path,
    *,
    ids: IdProvider,
    clock: Clock,
) -> WriteResult:
    """Create ``path`` exclusively and write the container, or return one refusal.

    The destination's directory is inspected first and a reparse point there
    is refused without opening anything; the destination's own entry is
    inspected next, without following it, and any existing entry, a dangling
    reparse point included, is refused before the create could follow it.
    ``owned`` becomes true only once the exclusive create has returned, so a
    failure before it leaves nothing to remove and an existing entry is never
    touched; a failure after it removes
    the partial file, and a removal that fails is swallowed because the
    refusal is the answer either way. The handlers draw no provider value.
    """
    data = normalized_container_bytes(series)
    digest = hashlib.sha256(data).hexdigest()
    owned = False
    complete = False
    try:
        if not _is_reparse_point(path.parent) and _is_absent(path):
            with path.open("xb") as handle:
                owned = True
                handle.write(data)
            complete = True
    except (OSError, ValueError):
        if owned:
            try:
                path.unlink()
            except OSError:
                pass
    if not complete:
        return refusal(
            RefusalCode.OUTPUT_DIRECTORY,
            line=WHOLE_INPUT_LINE,
            value_length=0,
            ids=ids,
            clock=clock,
        )
    container = NormalizedContainer(
        bytes_written=len(data),
        content_hash=digest,
        normalized_checksum=digest,
        row_count=len(series.rows),
    )
    return Success[NormalizedContainer](outcome="SUCCESS", value=container)


def raw_checksum(
    path: Path,
    *,
    max_bytes: int,
    ids: IdProvider,
    clock: Clock,
) -> RawChecksumResult:
    """Hash the exact bytes of ``path`` under the reader's ceiling, or refuse.

    The refusals are the reader's: a negative ceiling is ``SIZE_CEILING``
    before the path is inspected (value length ``0``), an unsuitable path or a
    failing read is ``INPUT_PATH`` and an input over the ceiling is
    ``SIZE_CEILING`` naming the bounded byte count, one past the ceiling.
    """
    if max_bytes < 0:
        return refusal(
            RefusalCode.SIZE_CEILING,
            line=WHOLE_INPUT_LINE,
            value_length=0,
            ids=ids,
            clock=clock,
        )
    data = _read_bounded(path, max_bytes)
    if data is None:
        return refusal(
            RefusalCode.INPUT_PATH,
            line=WHOLE_INPUT_LINE,
            value_length=0,
            ids=ids,
            clock=clock,
        )
    if len(data) > max_bytes:
        return refusal(
            RefusalCode.SIZE_CEILING,
            line=WHOLE_INPUT_LINE,
            value_length=len(data),
            ids=ids,
            clock=clock,
        )
    checksum = RawChecksum(
        sha256=hashlib.sha256(data).hexdigest(), byte_count=len(data)
    )
    return Success[RawChecksum](outcome="SUCCESS", value=checksum)


def _is_reparse_point(directory: Path) -> bool:
    """Whether ``directory`` itself carries the reparse-point attribute.

    ``lstat`` inspects the path without following it; its ``OSError`` for a
    missing directory and its ``ValueError`` for a path the platform rejects
    propagate to the writer, which converts them. On a platform without the
    attribute no directory carries it.
    """
    attributes = int(getattr(directory.lstat(), "st_file_attributes", 0))
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _is_absent(destination: Path) -> bool:
    """Whether no entry of any kind sits at ``destination``, without following it.

    ``lstat`` answers for the entry itself, so a file, a directory or a reparse
    point, dangling or not, is an existing entry and the answer is false: the
    exclusive create never reaches an entry it could follow, and a dangling
    link's missing target is never created. Only the platform's "no such
    entry" answer is absence; any other ``OSError`` and the ``ValueError`` for
    a path the platform rejects propagate to the writer, which converts them
    with nothing opened.
    """
    try:
        destination.lstat()
    except FileNotFoundError:
        return True
    return False
