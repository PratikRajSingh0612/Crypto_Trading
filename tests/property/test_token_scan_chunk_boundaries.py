"""Stage 9 plan 7.3 (T28.3-04, T28.4-03; specification 14.7:1018, 28.4:2114): a
token of 32-1024 url-safe bytes placed at every offset of a 0-3 chunk payload
under chunk sizes 1-4096 is found iff present; absence holds under arbitrary
split points; the token-shape detector finds a 32-byte run across any boundary
and never a 31-byte one. The token crosses the port as ``AttemptTokenMaterial``
(plan 4.1) over a handle the test opens. The test-side scan is ``bytes.find``
over the whole payload, an independent implementation that cross-checks the
streaming one."""

from __future__ import annotations

import hashlib
import itertools
import re
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.artifacts.hashing import HashScan, StreamingContentHasher
from crypto_lab.domain.engine_run import AttemptTokenMaterial
from doubles.experiments import RUN_ID

_URL_SAFE = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
_FILLER = b" \t\n\r.,;:!?@#%^&*()+=[]{}<>/\\|\"'`~\x00\x01\x7f\xff"
_SHAPE = re.compile(rb"[A-Za-z0-9_-]{32,}")
_counter = itertools.count()


def _mapped(raw: bytes, alphabet: bytes) -> bytes:
    return bytes(alphabet[value % len(alphabet)] for value in raw)


@st.composite
def _placements(draw: st.DrawFn) -> tuple[int, bytes, bytes, int]:
    chunk_size = draw(st.integers(min_value=1, max_value=4096))
    filler_length = draw(st.integers(min_value=0, max_value=3 * chunk_size))
    filler = _mapped(
        draw(st.binary(min_size=filler_length, max_size=filler_length)), _FILLER
    )
    token_length = draw(st.integers(min_value=32, max_value=1024))
    token = _mapped(
        draw(st.binary(min_size=token_length, max_size=token_length)), _URL_SAFE
    )
    offset = draw(st.integers(min_value=0, max_value=filler_length))
    return chunk_size, filler, token, offset


@st.composite
def _runs(draw: st.DrawFn) -> tuple[int, bytes, int]:
    chunk_size = draw(st.integers(min_value=1, max_value=4096))
    before = _mapped(draw(st.binary(min_size=0, max_size=2 * chunk_size)), _FILLER)
    after = _mapped(draw(st.binary(min_size=0, max_size=chunk_size)), _FILLER)
    run_length = draw(st.integers(min_value=1, max_value=48))
    run = _mapped(draw(st.binary(min_size=run_length, max_size=run_length)), _URL_SAFE)
    return chunk_size, before + run + after, run_length


def _write(tmp_path_factory: pytest.TempPathFactory, data: bytes) -> Path:
    root = tmp_path_factory.getbasetemp() / "token-scan"
    root.mkdir(exist_ok=True)
    path = root / f"{next(_counter)}.bin"
    path.write_bytes(data)
    return path


def _material(token: bytes) -> AttemptTokenMaterial:
    """The port's token boundary (plan 4.1): the drawn URL-safe bytes satisfy the
    ``AttemptToken`` grammar and are wrapped in the run's material."""
    return AttemptTokenMaterial(run_id=RUN_ID, attempt_token=token.decode("ascii"))


def _scan(
    hasher: StreamingContentHasher,
    path: Path,
    token: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
    *,
    detect_token_shape: bool,
) -> HashScan:
    with path.open("rb") as handle:
        return hasher.sha256_and_scan(
            handle, token, detect_token_shape=detect_token_shape
        )


@given(_placements())
@settings(deadline=None, max_examples=150)
def test_a_token_at_any_offset_is_found_under_any_chunk_size(
    tmp_path_factory: pytest.TempPathFactory,
    placement: tuple[int, bytes, bytes, int],
) -> None:
    chunk_size, filler, token, offset = placement
    data = filler[:offset] + token + filler[offset:]
    path = _write(tmp_path_factory, data)
    scan = _scan(
        StreamingContentHasher(chunk_size=chunk_size),
        path,
        _material(token),
        detect_token_shape=True,
    )
    assert scan.token_found is (data.find(token) >= 0)
    assert scan.token_found
    assert scan.token_shape_found
    assert scan.sha256 == hashlib.sha256(data).hexdigest()
    assert scan.size_bytes == len(data)


@given(_placements(), st.integers(min_value=0, max_value=1023))
@settings(deadline=None, max_examples=150)
def test_absence_holds_under_arbitrary_split_points(
    tmp_path_factory: pytest.TempPathFactory,
    placement: tuple[int, bytes, bytes, int],
    damaged_index: int,
) -> None:
    """Filler alone never carries the token or a token shape; a token with one
    byte replaced by filler is a near miss the carry must not stitch together."""
    chunk_size, filler, token, offset = placement
    hasher = StreamingContentHasher(chunk_size=chunk_size)
    absent = _write(tmp_path_factory, filler)
    scan = _scan(hasher, absent, _material(token), detect_token_shape=True)
    assert scan.token_found is False
    assert scan.token_shape_found is False
    assert scan.token_found is (filler.find(token) >= 0)
    position = damaged_index % len(token)
    damaged = token[:position] + _FILLER[:1] + token[position + 1 :]
    data = filler[:offset] + damaged + filler[offset:]
    near_miss = _write(tmp_path_factory, data)
    scan = _scan(hasher, near_miss, _material(token), detect_token_shape=False)
    assert scan.token_found is (data.find(token) >= 0)
    assert scan.token_found is False
    assert scan.sha256 == hashlib.sha256(data).hexdigest()


@given(_runs())
@settings(deadline=None, max_examples=150)
def test_a_token_shape_is_found_iff_a_run_reaches_thirty_two(
    tmp_path_factory: pytest.TempPathFactory, case: tuple[int, bytes, int]
) -> None:
    chunk_size, data, run_length = case
    path = _write(tmp_path_factory, data)
    scan = _scan(
        StreamingContentHasher(chunk_size=chunk_size),
        path,
        MISSING,
        detect_token_shape=True,
    )
    assert scan.token_shape_found is (run_length >= 32)
    assert scan.token_shape_found is (_SHAPE.search(data) is not None)
    assert scan.token_found is False
