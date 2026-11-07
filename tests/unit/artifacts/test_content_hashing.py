"""Stage 9 Task 4: streaming SHA-256 and the exact-byte token scan (plan 4.1, 6.4;
specification 10.2:472, 14.7:1018, 28.4:2114; R10.2-01, R10.2-08, R14.7-08).

``StreamingContentHasher`` reads fixed chunks from a caller-owned ``BinaryIO`` and
never the whole file -- it neither reopens a path nor closes the handle (plan 4.1:
``sha256_stream(source) -> Sha256``, ``sha256_and_scan(source, token)``); the token
crosses the port as ``AttemptTokenMaterial | MISSING`` and its bytes exist only
inside the scan; the scan carries ``len(token) - 1`` bytes across every chunk
boundary so a split token is found; the token-shape detector of the audit
redaction is restated here as bytes and pinned equal; the result is a boolean and
no offset is ever recorded.
"""

from __future__ import annotations

import ast
import builtins
import dataclasses
import hashlib
import inspect
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest
from pydantic.experimental.missing_sentinel import MISSING
from test_candidate_validation import (
    adapter_candidate,
    failed_with,
    stage_candidate,
    succeeded,
    validate,
)

from crypto_lab.artifacts import hashing as hashing_module
from crypto_lab.artifacts.diagnostics import SECURITY_SENSITIVE_MATERIAL_LEAKAGE
from crypto_lab.artifacts.hashing import (
    DEFAULT_CHUNK_BYTES,
    TOKEN_SHAPE_PATTERN,
    ContentHasher,
    HashScan,
    StreamingContentHasher,
)
from crypto_lab.audit.redaction import TOKEN_SHAPE_PATTERN as AUDIT_TOKEN_SHAPE_PATTERN
from crypto_lab.domain.engine_run import AttemptTokenMaterial
from doubles.experiments import ATTEMPT_TOKEN, RUN_ID

_TOKEN = AttemptTokenMaterial(run_id=RUN_ID, attempt_token=ATTEMPT_TOKEN)
_TOKEN_BYTES = ATTEMPT_TOKEN.encode("utf-8")
_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _material(text: str) -> AttemptTokenMaterial:
    return AttemptTokenMaterial(run_id=RUN_ID, attempt_token=text)


def _stream(hasher: StreamingContentHasher, path: Path) -> str:
    """Open ``path`` here, hand the handle to the hasher, prove it is left open."""
    with path.open("rb") as handle:
        digest = hasher.sha256_stream(handle)
        assert not handle.closed
    return digest


def _scan(
    hasher: StreamingContentHasher,
    path: Path,
    token: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
    *,
    detect_token_shape: bool = False,
) -> HashScan:
    with path.open("rb") as handle:
        scan = hasher.sha256_and_scan(
            handle, token, detect_token_shape=detect_token_shape
        )
        assert not handle.closed
    return scan


class _ReadSpy:
    """A stream exposing ``read`` alone: the hasher may neither seek nor close."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.requested: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.requested.append(size)
        data: bytes = self._inner.read(size)
        return data


# --- Plan Task 4 Step 1 ---------------------------------------------------------------


def test_sha256_is_the_authoritative_digest(tmp_path: Path) -> None:
    """Specification 10.2: SHA-256 over the exact bytes, known vectors."""
    hasher = StreamingContentHasher()
    assert isinstance(hasher, ContentHasher)
    abc = tmp_path / "abc.bin"
    abc.write_bytes(b"abc")
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    assert _stream(hasher, abc) == _ABC
    assert _stream(hasher, empty) == _EMPTY
    assert hasher.sha256_stream(BytesIO(b"abc")) == _ABC
    assert type(hasher.sha256_stream(BytesIO(b""))) is str
    scan = _scan(hasher, abc, _TOKEN, detect_token_shape=True)
    assert scan == HashScan(
        sha256=_ABC, size_bytes=3, token_found=False, token_shape_found=False
    )
    assert _scan(hasher, empty, MISSING) == HashScan(
        sha256=_EMPTY, size_bytes=0, token_found=False, token_shape_found=False
    )
    assert DEFAULT_CHUNK_BYTES == 2**20
    assert _stream(StreamingContentHasher(chunk_size=1), abc) == _ABC
    assert _stream(StreamingContentHasher(chunk_size=2), empty) == _EMPTY


def test_streaming_never_reads_whole_file(tmp_path: Path) -> None:
    """R10.2-08: a 64 MiB fixture is read in fixed 1 MiB requests, never whole,
    through both stream entry points."""
    size = 64 * 2**20
    big = tmp_path / "sparse.bin"
    with big.open("wb") as handle:
        handle.truncate(size)
    expected = hashlib.sha256()
    with big.open("rb") as reader:
        while chunk := reader.read(DEFAULT_CHUNK_BYTES):
            expected.update(chunk)
    hasher = StreamingContentHasher()
    with big.open("rb") as handle:
        spy = _ReadSpy(handle)
        digest = hasher.sha256_stream(spy)  # type: ignore[arg-type]
        assert not handle.closed
    assert set(spy.requested) == {DEFAULT_CHUNK_BYTES}
    assert len(spy.requested) == 65  # 64 full chunks and the empty read that ends it
    assert digest == expected.hexdigest()
    with big.open("rb") as handle:
        spy = _ReadSpy(handle)
        scan = hasher.sha256_and_scan(spy, MISSING)  # type: ignore[arg-type]
    assert set(spy.requested) == {DEFAULT_CHUNK_BYTES}
    assert len(spy.requested) == 65
    assert (scan.sha256, scan.size_bytes) == (expected.hexdigest(), size)


def test_stream_entry_points_take_a_caller_owned_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan 4.1: both entry points consume an already-open ``BinaryIO`` from its
    current position; no path is reopened and the caller's handle stays open."""
    data = b"0123456789" + _TOKEN_BYTES + b"abcdef"
    path = tmp_path / "owned.bin"
    path.write_bytes(data)
    hasher = StreamingContentHasher(chunk_size=7)

    def refuse_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("the hasher opened a path")

    with path.open("rb") as handle, monkeypatch.context() as patched:
        patched.setattr(Path, "open", refuse_open)
        patched.setattr(builtins, "open", refuse_open)
        assert hasher.sha256_stream(handle) == _digest(data)
        assert not handle.closed
        assert handle.read() == b""  # left at the end, never rewound
        handle.seek(0)
        scan = hasher.sha256_and_scan(handle, _TOKEN, detect_token_shape=False)
        assert not handle.closed
        assert scan == HashScan(
            sha256=_digest(data),
            size_bytes=len(data),
            token_found=True,
            token_shape_found=False,
        )
        handle.seek(10)
        assert hasher.sha256_stream(handle) == _digest(data[10:])
        handle.seek(10)
        assert hasher.sha256_and_scan(handle, _TOKEN).token_found is True
        handle.seek(11)
        assert hasher.sha256_and_scan(handle, _TOKEN).token_found is False
        assert not handle.closed
    assert handle.closed  # closed by the caller's ``with``, never before
    memory = BytesIO(data)
    assert hasher.sha256_and_scan(memory, _TOKEN) == scan
    assert not memory.closed


def test_token_found_across_chunk_boundary(tmp_path: Path) -> None:
    straddling = b"....." + _TOKEN_BYTES + b"...."
    path = tmp_path / "straddle.bin"
    path.write_bytes(straddling)
    for chunk_size in (1, 2, 7, 8, 31, 32, 33, len(straddling), DEFAULT_CHUNK_BYTES):
        hasher = StreamingContentHasher(chunk_size=chunk_size)
        scan = _scan(hasher, path, _TOKEN)
        assert scan.token_found, chunk_size
        assert (scan.sha256, scan.size_bytes) == (_digest(straddling), len(straddling))
    almost = tmp_path / "almost.bin"
    almost.write_bytes(b"....." + _TOKEN_BYTES[:-1] + b"B....")
    for chunk_size in (1, 8, 32, 4096):
        hasher = StreamingContentHasher(chunk_size=chunk_size)
        scan = _scan(hasher, almost, _TOKEN)
        assert not scan.token_found, chunk_size
    long_token = "T" * 100
    longer = tmp_path / "longer.bin"
    longer.write_bytes(b"..." + long_token.encode("ascii") + b".")
    for chunk_size in (1, 8, 99, 100, 101):
        hasher = StreamingContentHasher(chunk_size=chunk_size)
        scan = _scan(hasher, longer, _material(long_token))
        assert scan.token_found, chunk_size
        shorter = _scan(hasher, longer, _material(long_token + "T"))
        assert not shorter.token_found, chunk_size


def test_token_shape_is_detected_only_on_request_and_across_boundaries(
    tmp_path: Path,
) -> None:
    """The audit redaction's shape rule, restated as bytes and pinned equal; a
    31-byte run is not a token shape and a 32-byte run split anywhere is."""
    assert TOKEN_SHAPE_PATTERN == AUDIT_TOKEN_SHAPE_PATTERN
    assert TOKEN_SHAPE_PATTERN == r"[A-Za-z0-9_-]{32,}"  # noqa: S105 - a grammar
    digest_text = b'{"hash": "' + b"7" * 64 + b'"}'
    shaped_path = tmp_path / "shaped.json"
    shaped_path.write_bytes(digest_text)
    for chunk_size in (1, 5, 32, 64, 4096):
        hasher = StreamingContentHasher(chunk_size=chunk_size)
        shaped = _scan(hasher, shaped_path, _TOKEN, detect_token_shape=True)
        assert (shaped.token_found, shaped.token_shape_found) == (False, True)
        plain = _scan(hasher, shaped_path, _TOKEN, detect_token_shape=False)
        assert (plain.token_found, plain.token_shape_found) == (False, False)
        no_token = _scan(hasher, shaped_path, MISSING, detect_token_shape=True)
        assert (no_token.token_found, no_token.token_shape_found) == (False, True)
        # The plan 4.1 two-argument call shape: no shape detection unless asked.
        with shaped_path.open("rb") as handle:
            default = hasher.sha256_and_scan(handle, MISSING)
        assert (default.token_found, default.token_shape_found) == (False, False)
    for run_length, expected in ((31, False), (32, True)):
        run_path = tmp_path / f"run{run_length}.txt"
        run_path.write_bytes(b"..." + b"x" * run_length + b"...")
        for chunk_size in (1, 3, 31, 32, 4096):
            hasher = StreamingContentHasher(chunk_size=chunk_size)
            scan = _scan(hasher, run_path, MISSING, detect_token_shape=True)
            assert scan.token_shape_found is expected, (run_length, chunk_size)


def test_binary_candidate_with_token_rejected(tmp_path: Path) -> None:
    """R14.7-08, R19.1-13: a native or binary candidate carrying the raw token is
    sensitive-material leakage and is never finalized."""
    data = b"\x00\x01binary" + _TOKEN_BYTES + b"\xff\xfe"
    candidate = adapter_candidate(data)
    validation = validate(candidate, stage_candidate(tmp_path, candidate, data))
    message = failed_with(validation, "REDACTION", SECURITY_SENSITIVE_MATERIAL_LEAKAGE)
    assert ATTEMPT_TOKEN not in message
    clean_bytes = b"\x00\x01binary" + b"-" * 10 + b"\xff\xfe"
    clean = adapter_candidate(clean_bytes)
    succeeded(validate(clean, stage_candidate(tmp_path / "clean", clean, clean_bytes)))


def test_offset_never_recorded() -> None:
    """14.7:1014 "never sample bytes": the scan is a boolean; nothing names where.
    The module also never opens, seeks or closes: the handle is the caller's, and
    no token-bearing record exists beside the two result shapes."""
    assert [field.name for field in dataclasses.fields(HashScan)] == [
        "sha256",
        "size_bytes",
        "token_found",
        "token_shape_found",
    ]
    assert not hasattr(hashing_module, "ContentDigest")
    source = inspect.getsource(hashing_module)
    tree = ast.parse(source)
    names = {
        node.id if isinstance(node, ast.Name) else node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Name | ast.Attribute)
    }
    assert not {"offset", "position", "index", "find", "sample"} & names
    assert not {"open", "close", "seek", "tell", "fileno", "Path"} & names
    assert [node.name for node in tree.body if isinstance(node, ast.ClassDef)] == [
        "HashScan",
        "ContentHasher",
        "StreamingContentHasher",
    ]
    scan = HashScan(sha256=_ABC, size_bytes=3, token_found=True, token_shape_found=True)
    with pytest.raises(dataclasses.FrozenInstanceError):
        scan.token_found = False  # type: ignore[misc]


# --- Contract and hook -------------------------------------------------------------


def test_the_hasher_refuses_bad_arguments_and_propagates_read_failures(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="chunk size"):
        StreamingContentHasher(chunk_size=0)
    with pytest.raises(TypeError, match="chunk size"):
        StreamingContentHasher(chunk_size="1")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="on_chunk"):
        StreamingContentHasher(on_chunk="hook")  # type: ignore[arg-type]
    hasher = StreamingContentHasher()
    assert hasher.chunk_size == DEFAULT_CHUNK_BYTES
    assert StreamingContentHasher(chunk_size=4).chunk_size == 4
    path = tmp_path / "abc.bin"
    path.write_bytes(b"abc")
    with pytest.raises(TypeError, match="readable binary stream"):
        hasher.sha256_stream(path)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="readable binary stream"):
        hasher.sha256_stream(str(path))  # type: ignore[arg-type]
    with (
        path.open("r", encoding="utf-8") as text,
        pytest.raises(TypeError, match="bytes"),
    ):
        hasher.sha256_stream(text)  # type: ignore[arg-type]
    with path.open("rb") as handle:
        with pytest.raises(TypeError, match="token"):
            hasher.sha256_and_scan(handle, _TOKEN_BYTES)
        with pytest.raises(TypeError, match="token"):
            hasher.sha256_and_scan(handle, None)
        with pytest.raises(TypeError, match="token"):
            hasher.sha256_and_scan(handle, ATTEMPT_TOKEN)
        assert handle.read() == b"abc"  # a refused token read nothing
    closed = path.open("rb")
    closed.close()
    with pytest.raises(ValueError, match="closed file"):
        hasher.sha256_stream(closed)

    class _FailingReader:
        def read(self, size: int = -1) -> bytes:
            raise OSError(5, "Input/output error")

    with pytest.raises(OSError, match="Input/output error"):
        hasher.sha256_stream(_FailingReader())  # type: ignore[arg-type]
    with pytest.raises(OSError, match="Input/output error"):
        hasher.sha256_and_scan(_FailingReader(), _TOKEN)  # type: ignore[arg-type]


def test_the_on_chunk_hook_observes_every_read(tmp_path: Path) -> None:
    observed: list[int] = []
    hasher = StreamingContentHasher(chunk_size=4, on_chunk=observed.append)
    path = tmp_path / "ten.bin"
    path.write_bytes(b"0123456789")
    digest = _stream(hasher, path)
    assert observed == [4, 4, 2]
    assert digest == _digest(b"0123456789")
    observed.clear()
    scan = _scan(hasher, path, _material("3456789" * 5))
    assert observed == [4, 4, 2]
    assert scan.token_found is False
    observed.clear()
    assert _scan(hasher, path, MISSING).size_bytes == 10
    assert observed == [4, 4, 2]
