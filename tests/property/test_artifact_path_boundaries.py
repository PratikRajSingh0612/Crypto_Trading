"""Stage 9 plan 7.3 (T28.4-01; specification 28.4:2108): over separators,
traversal segments, drive and UNC prefixes, Unicode in both normalization forms,
alternate-data-stream suffixes, reserved device names and long segments,
``confine_candidate_path`` accepts exactly the strings
``validate_relative_candidate_path`` accepts (the ADS rule is already inside that
grammar) and a confined leaf never resolves outside its root."""

from __future__ import annotations

import unicodedata
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from crypto_lab.adapters.paths import validate_relative_candidate_path
from crypto_lab.artifacts.paths import (
    confine_candidate_path,
    is_within_root,
    lexical_candidate_path,
)
from crypto_lab.domain.results import Success

_NOW = datetime(2026, 8, 10, 1, 2, 3, tzinfo=UTC)
_PLAIN = "abcXYZ019._-"
_NFC = unicodedata.normalize("NFC", "r\u00e9sum\u00e9")
_NFD = unicodedata.normalize("NFD", "r\u00e9sum\u00e9")
_HOSTILE = (
    "..",
    ".",
    "/",
    "\\",
    ":",
    "C:",
    "C:\\",
    "//server/share",
    "\\\\server\\share",
    "\\\\?\\",
    ":stream",
    ":$DATA",
    "aux",
    "CON",
    "com1.txt",
    "nul.bin",
    "LPT9",
    "prn.",
    "trailing.",
    " ",
    "%41",
    _NFC,
    _NFD,
    "a" * 255,
    "a" * 256,
    "/".join(["s"] * 32),
    "/".join(["s"] * 33),
)
#: The pieces that stay hostile however they are spliced into a valid path: a
#: reserved stem or a 255-character segment is hostile only on its own, so the
#: parity property carries those and this subset drives the refusal property.
_ALWAYS_HOSTILE = (
    "..",
    ".",
    "/",
    "\\",
    ":",
    "C:",
    "C:\\",
    "//server/share",
    "\\\\server\\share",
    "\\\\?\\",
    ":stream",
    ":$DATA",
    " ",
    "%41",
    _NFC,
    _NFD,
    "a" * 256,
    "/".join(["s"] * 33),
)
_pieces = st.one_of(
    st.text(alphabet=_PLAIN, min_size=1, max_size=8), st.sampled_from(_HOSTILE)
)
_separators = st.sampled_from(["/", "", "\\", "//", "/./", "/../"])
_relative_paths = st.lists(st.tuples(_pieces, _separators), min_size=1, max_size=6).map(
    lambda parts: "".join(piece + separator for piece, separator in parts)
)
_physical_segment = st.tuples(
    st.text(alphabet="abcdef0123456789", min_size=1, max_size=1),
    st.text(alphabet="abcdef0123456789_-", min_size=0, max_size=5),
).map("".join)
_physical_segments = st.lists(_physical_segment, min_size=1, max_size=4).map("/".join)


def _accepts(validator: object, value: str) -> bool:
    assert callable(validator)
    try:
        validator(value)
    except ValueError:
        return False
    return True


@given(_relative_paths)
@settings(deadline=None, max_examples=300)
def test_confinement_grammar_agrees_with_the_adapter_grammar(relative: str) -> None:
    ours = _accepts(lexical_candidate_path, relative)
    theirs = _accepts(validate_relative_candidate_path, relative)
    assert ours == theirs, relative
    if ours:
        pure = PureWindowsPath(relative)
        assert not pure.is_absolute()
        assert pure.drive == ""
        assert ".." not in pure.parts
        assert ":" not in relative
        assert "\\" not in relative
        assert relative.isascii()


@given(_physical_segments)
@settings(deadline=None, max_examples=60)
def test_a_confined_leaf_resolves_inside_its_root(
    tmp_path_factory: pytest.TempPathFactory, relative: str
) -> None:
    root = tmp_path_factory.mktemp("confine")
    leaf = root.joinpath(*relative.split("/"))
    leaf.parent.mkdir(parents=True, exist_ok=True)
    leaf.write_bytes(b"x")
    result = confine_candidate_path(root, relative, now_utc=_NOW)
    assert isinstance(result, Success), (relative, result)
    confined = result.value
    assert confined.relative == relative
    assert confined.path == leaf
    resolved_root = root.resolve(strict=True)
    assert is_within_root(confined.path.resolve(strict=True), resolved_root)
    assert not is_within_root(resolved_root.parent / "sibling", resolved_root)


@given(st.sampled_from(_ALWAYS_HOSTILE), _physical_segments)
@settings(deadline=None, max_examples=60)
def test_a_hostile_piece_anywhere_is_refused_lexically(
    hostile: str, relative: str
) -> None:
    """Every always-hostile piece, spliced into an otherwise valid path, is refused
    by the lexical half, so it never reaches ``lstat`` or ``resolve``."""
    assert _accepts(lexical_candidate_path, relative)
    for spliced in (
        f"{hostile}/{relative}",
        f"{relative}/{hostile}",
        f"{relative}{hostile}",
    ):
        assert not _accepts(lexical_candidate_path, spliced), spliced
        assert not _accepts(validate_relative_candidate_path, spliced), spliced
    unc_root = Path("//server/share/root")
    refused = confine_candidate_path(unc_root, relative, now_utc=_NOW)
    assert not isinstance(refused, Success)
