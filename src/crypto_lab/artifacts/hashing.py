"""Streaming SHA-256 and the exact-byte raw-token scan over staged candidates.

Stage 9 plan 4.1 and 6.4 under specification 10.2:472 ("stream large-file
hashing") and 14.7:1018 ("a streaming exact-byte scan for the active raw token").
``ContentHasher`` is the port the finalizer consumes, in the plan 4.1 form --
``sha256_stream(source) -> Sha256`` and ``sha256_and_scan(source, token) ->
HashScan`` over a caller-owned ``BinaryIO``. ``StreamingContentHasher`` reads
fixed chunks of ``chunk_size`` bytes from the handle's current position until the
stream is exhausted and never the whole file; it opens no path, never seeks and
never closes -- the handle, its position and its lifetime are the caller's, so the
store can hash through the very handle whose ``fstat`` identity it has checked
(plan 6.5, reading 18). The token crosses the port as
``AttemptTokenMaterial | MISSING``; its bytes exist only as a local of the scan
and are never recorded. ``sha256_and_scan`` searches each chunk together with a
carry of the previous bytes -- ``len(token) - 1`` for the exact token, 31 for the
token shape -- so a token or a token-shaped run split across any chunk boundary
is still found. The token-shape detector is the audit redaction's rule restated
as bytes (``artifacts`` may not import ``audit``, plan 2.6; pinned equal by test)
and runs only when the caller asks through the keyword ``detect_token_shape``,
which the validation does for text kinds of ``EVIDENCE`` candidates. The result
is two booleans; where a match lies is never recorded (14.7:1014 "never sample
bytes").

Reconciled against plan 4.1: ``HashScan`` carries no ``identity_before`` or
``identity_after`` -- the ``fstat`` identity is observed by ``artifacts/store.py``,
the one ``os`` importer (plan 2.6), around the stream it hands in -- and carries
``token_shape_found`` beside ``token_found`` because the shape rule cannot be
imported from ``audit``. ``on_chunk`` is a probe-free hook called with each
chunk's length as it is read; production passes none, and the Windows platform
test uses it to append to the file between chunks.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO, Final, Protocol, runtime_checkable

from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.engine_run import AttemptTokenMaterial
from crypto_lab.domain.identifiers import Sha256

#: Plan 6.4: the fixed read size.
DEFAULT_CHUNK_BYTES: Final = 1_048_576
#: ``audit.redaction.TOKEN_SHAPE_PATTERN`` restated: the ``AttemptToken`` alphabet
#: at its 32-character minimum with no upper bound.
TOKEN_SHAPE_PATTERN: Final = r"[A-Za-z0-9_-]{32,}"  # noqa: S105 - a grammar, not a secret
_TOKEN_SHAPE: Final = re.compile(TOKEN_SHAPE_PATTERN.encode("ascii"))
_MIN_TOKEN_SHAPE_LENGTH: Final = 32


@dataclass(frozen=True, slots=True)
class HashScan:
    """The digest and byte count beside the two scan booleans; no offset is ever
    recorded."""

    sha256: str
    size_bytes: int
    token_found: bool
    token_shape_found: bool


@runtime_checkable
class ContentHasher(Protocol):
    """Plan 4.1 (specification 10.2 and 14.7): streamed hashing with the exact-byte
    scan over a caller-owned binary stream."""

    def sha256_stream(self, source: BinaryIO) -> Sha256:
        """Hash ``source`` from its current position in fixed chunks."""

    def sha256_and_scan(
        self,
        source: BinaryIO,
        token: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
        *,
        detect_token_shape: bool = False,
    ) -> HashScan:
        """Hash ``source`` and scan it for the raw token of ``token`` and, on
        request, a token shape."""


def _no_hook(length: int) -> None:
    del length


class StreamingContentHasher:
    """The one ``ContentHasher`` of Stage 9 (plan 6.4)."""

    def __init__(
        self,
        chunk_size: int = DEFAULT_CHUNK_BYTES,
        *,
        on_chunk: Callable[[int], None] | None = None,
    ) -> None:
        if type(chunk_size) is not int:
            raise TypeError("chunk size must be a built-in integer")
        if chunk_size < 1:
            raise ValueError("chunk size must be positive")
        if on_chunk is not None and not callable(on_chunk):
            raise TypeError("on_chunk must be callable")
        self._chunk_size = chunk_size
        self._on_chunk: Callable[[int], None] = (
            _no_hook if on_chunk is None else on_chunk
        )

    @property
    def chunk_size(self) -> int:
        return self._chunk_size

    def sha256_stream(self, source: BinaryIO) -> Sha256:
        return self._stream(source, needle=None, detect_token_shape=False).sha256

    def sha256_and_scan(
        self,
        source: BinaryIO,
        token: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
        *,
        detect_token_shape: bool = False,
    ) -> HashScan:
        needle: bytes | None
        if isinstance(token, AttemptTokenMaterial):
            needle = token.attempt_token.encode("utf-8")
        elif token is MISSING:
            needle = None
        else:
            raise TypeError("token must be AttemptTokenMaterial or MISSING")
        if type(detect_token_shape) is not bool:
            raise TypeError("detect_token_shape must be a bool")
        return self._stream(
            source, needle=needle, detect_token_shape=detect_token_shape
        )

    def _stream(
        self, source: BinaryIO, *, needle: bytes | None, detect_token_shape: bool
    ) -> HashScan:
        """Read ``source`` from its current position to exhaustion in fixed chunks;
        the raw token bytes, when any, live in ``needle`` alone."""
        if not callable(getattr(source, "read", None)):
            raise TypeError("source must be a readable binary stream")
        digest = hashlib.sha256()
        size = 0
        token_found = False
        shape_found = False
        carry_length = 0
        if needle is not None:
            carry_length = max(carry_length, len(needle) - 1)
        if detect_token_shape:
            carry_length = max(carry_length, _MIN_TOKEN_SHAPE_LENGTH - 1)
        scanning = needle is not None or detect_token_shape
        carry = b""
        while chunk := source.read(self._chunk_size):
            if type(chunk) is not bytes:
                raise TypeError("source must yield bytes")
            self._on_chunk(len(chunk))
            digest.update(chunk)
            size += len(chunk)
            if not scanning:
                continue
            window = carry + chunk
            if needle is not None and not token_found and needle in window:
                token_found = True
            if (
                detect_token_shape
                and not shape_found
                and _TOKEN_SHAPE.search(window) is not None
            ):
                shape_found = True
            carry = window[-carry_length:] if carry_length else b""
        return HashScan(
            sha256=digest.hexdigest(),
            size_bytes=size,
            token_found=token_found,
            token_shape_found=shape_found,
        )


__all__ = (
    "DEFAULT_CHUNK_BYTES",
    "TOKEN_SHAPE_PATTERN",
    "ContentHasher",
    "HashScan",
    "StreamingContentHasher",
)
