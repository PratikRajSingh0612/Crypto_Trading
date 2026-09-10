"""Stage 6 Task 1: the candidate-path grammar over generated text (plan 3.3).

Two independent oracles bound the runtime from both sides. The first is the
published schema pattern itself, compiled with Python's `re`, so runtime and
schema are proven to accept exactly the same strings; the second is a
re-statement of the section 3.3 rules written here in plain Python, so a defect
shared by the runtime and its published pattern is still caught.
"""

from __future__ import annotations

import re

from hypothesis import given
from hypothesis import strategies as st
from pydantic import TypeAdapter, ValidationError

from crypto_lab.adapters.limits import (
    MAX_PATH_SEGMENTS,
    MAX_RELATIVE_PATH_CHARACTERS,
    MAX_SEGMENT_CHARACTERS,
)
from crypto_lab.adapters.paths import (
    RelativeCandidatePath,
    validate_relative_candidate_path,
)

_ADAPTER: TypeAdapter[str] = TypeAdapter(RelativeCandidatePath)
_SCHEMA = _ADAPTER.json_schema()
_PUBLISHED = re.compile(str(_SCHEMA["pattern"]))
_PUBLISHED_MIN = int(_SCHEMA["minLength"])
_PUBLISHED_MAX = int(_SCHEMA["maxLength"])
_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_RESERVED = frozenset(
    {
        "AUX",
        "CON",
        "NUL",
        "PRN",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
    }
)
_PIECES = [
    *"abcXYZ019._-/\\: %\t",
    "ä",
    "..",
    "CON",
    "con",
    "COM1",
    "COM10",
    "LPT9",
    "a.",
    "//",
    "%2e",
]


def _runtime_accepts(value: str) -> bool:
    try:
        validate_relative_candidate_path(value)
    except ValueError:
        return False
    return True


def _published_accepts(value: str) -> bool:
    """The three published constraints together: pattern, minLength, maxLength."""
    return (
        _PUBLISHED.fullmatch(value) is not None
        and _PUBLISHED_MIN <= len(value) <= _PUBLISHED_MAX
    )


def _adapter_accepts(value: str) -> bool:
    try:
        _ADAPTER.validate_python(value)
    except ValidationError:
        return False
    return True


def _segment_is_valid(segment: str) -> bool:
    return (
        1 <= len(segment) <= MAX_SEGMENT_CHARACTERS
        and _SEGMENT.fullmatch(segment) is not None
        and not segment.endswith(".")
        and segment.partition(".")[0].upper() not in _RESERVED
    )


def _rules_accept(value: str) -> bool:
    segments = value.split("/")
    return (
        1 <= len(value) <= MAX_RELATIVE_PATH_CHARACTERS
        and len(segments) <= MAX_PATH_SEGMENTS
        and all(_segment_is_valid(segment) for segment in segments)
    )


@given(st.lists(st.sampled_from(_PIECES), min_size=0, max_size=40).map("".join))
def test_the_runtime_accepts_exactly_the_published_grammar(value: str) -> None:
    accepted = _runtime_accepts(value)
    assert accepted == _published_accepts(value)
    assert accepted == _adapter_accepts(value)
    assert accepted == _rules_accept(value)


@given(
    st.lists(
        st.text(alphabet=st.sampled_from("abcXYZ019._-"), min_size=1, max_size=8),
        min_size=1,
        max_size=40,
    )
)
def test_segment_joins_are_accepted_exactly_when_every_segment_rule_holds(
    segments: list[str],
) -> None:
    value = "/".join(segments)
    assert _runtime_accepts(value) == _rules_accept(value)
    assert _runtime_accepts(value) == _published_accepts(value)


@given(st.integers(min_value=1, max_value=600))
def test_a_single_segment_is_accepted_exactly_up_to_the_segment_bound(
    length: int,
) -> None:
    value = "a" * length
    expected = length <= MAX_SEGMENT_CHARACTERS
    assert _runtime_accepts(value) is expected
    assert _published_accepts(value) is expected


@given(st.integers(min_value=1, max_value=40))
def test_segment_count_is_accepted_exactly_up_to_the_segment_count_bound(
    count: int,
) -> None:
    value = "/".join(["a"] * count)
    expected = count <= MAX_PATH_SEGMENTS
    assert _runtime_accepts(value) is expected
    assert _published_accepts(value) is expected


@given(
    st.integers(min_value=3, max_value=5),
    st.integers(
        min_value=MAX_RELATIVE_PATH_CHARACTERS - 3,
        max_value=MAX_RELATIVE_PATH_CHARACTERS + 3,
    ),
)
def test_total_length_is_accepted_exactly_up_to_the_path_bound(
    segments: int,
    total: int,
) -> None:
    """Three to five segments keep every segment under 255 characters, so only
    the total bound decides, on both the runtime and the published side."""
    body = total - (segments - 1)
    sizes = [
        body // segments + (1 if index < body % segments else 0)
        for index in range(segments)
    ]
    value = "/".join("a" * size for size in sizes)
    assert len(value) == total
    assert max(sizes) <= MAX_SEGMENT_CHARACTERS
    expected = total <= MAX_RELATIVE_PATH_CHARACTERS
    assert _runtime_accepts(value) is expected
    assert _published_accepts(value) is expected


@given(
    stem=st.sampled_from(sorted(_RESERVED)),
    casing=st.lists(st.booleans(), min_size=4, max_size=4),
    suffix=st.text(alphabet=st.sampled_from("abc0"), max_size=3),
    prefixed=st.booleans(),
)
def test_every_reserved_stem_is_rejected_and_every_longer_stem_accepted(
    stem: str,
    casing: list[bool],
    suffix: str,
    prefixed: bool,
) -> None:
    spelled = "".join(
        character.lower() if lower else character
        for character, lower in zip(stem, casing, strict=False)
    )
    reserved = f"{spelled}.{suffix}" if suffix else spelled
    lookalike = f"{spelled}{suffix or 'x'}"
    if prefixed:
        reserved = f"dir/{reserved}"
        lookalike = f"dir/{lookalike}"
    assert not _runtime_accepts(reserved)
    assert not _published_accepts(reserved)
    assert _runtime_accepts(lookalike)
    assert _published_accepts(lookalike)
