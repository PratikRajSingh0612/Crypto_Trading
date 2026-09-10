"""The textual candidate-path grammar (Stage 6 plan section 3.3).

Specification 15.5 requires every adapter-supplied candidate path to be
"relative, normalized, free of drive prefixes, free of alternate data-stream
syntax, and free of ``..`` traversal". This module is the plan's declared,
deliberately over-strict textual reading of that rule for a Windows host:

1. total length 1 through ``MAX_RELATIVE_PATH_CHARACTERS``; 1 through
   ``MAX_PATH_SEGMENTS`` segments separated by exactly one ``/``; every segment
   1 through ``MAX_SEGMENT_CHARACTERS`` characters matching
   ``^[A-Za-z0-9][A-Za-z0-9._-]*$``;
2. hence rejected by construction: a leading or trailing ``/``, an empty
   segment, any ``\\``, ``:`` (drive and alternate-data-stream syntax),
   whitespace, control characters, non-ASCII text, percent signs, UNC or device
   prefixes;
3. a segment may not be ``.`` or ``..`` and may not end in ``.`` (Windows
   trailing-dot aliasing);
4. a segment whose stem before the first ``.`` is, case-insensitively, ``CON``,
   ``PRN``, ``AUX``, ``NUL``, ``COM1``-``COM9`` or ``LPT1``-``LPT9`` is rejected.

Containment against a real root and link or reparse-point rejection remain
Stage 7 and Stage 9 work; Stage 6 asserts the text alone and never touches the
filesystem. ``datasets/models.py`` carries the same reserved-stem, trailing-dot
and dot-segment rejections for registry paths; ``adapters`` may import only
``domain``, so this is a separate grammar kept textually aligned with it.

The published schema pattern encodes every rule above, including the reserved
stems and the trailing dot, so the committed bytes are exact rather than a
superset (plan 12.4); ``tests/property/test_candidate_path_boundaries.py``
proves runtime and pattern agree over generated text.
"""

from __future__ import annotations

import re
from typing import Annotated, Final

from pydantic import AfterValidator, StringConstraints, WithJsonSchema

from crypto_lab.adapters.limits import (
    MAX_PATH_SEGMENTS,
    MAX_RELATIVE_PATH_CHARACTERS,
    MAX_SEGMENT_CHARACTERS,
)
from crypto_lab.domain.identifiers import exact_string_schema

_SEGMENT: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_RESERVED_STEMS: Final[frozenset[str]] = frozenset(
    {
        "AUX",
        "CON",
        "NUL",
        "PRN",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
    }
)
# The published grammar. A segment is one alphanumeric character, or an
# alphanumeric character, up to 253 body characters and a final character that
# is not a dot; a reserved stem is refused by a lookahead at the segment start
# when it is followed by a dot, a separator or the end of the string. Interior
# end-of-string is spelled `(?![\s\S])`, never `$`, matching the project rule
# that `exact_string_schema` applies to the terminal assertion.
_RESERVED_STEM_LOOKAHEAD: Final = (
    r"(?!(?:[Aa][Uu][Xx]|[Cc][Oo][Nn]|[Nn][Uu][Ll]|[Pp][Rr][Nn]|"
    r"[Cc][Oo][Mm][1-9]|[Ll][Pp][Tt][1-9])(?:\.|/|(?![\s\S])))"
)
_PUBLISHED_SEGMENT: Final = (
    _RESERVED_STEM_LOOKAHEAD
    + r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,"
    + str(MAX_SEGMENT_CHARACTERS - 2)
    + r"}[A-Za-z0-9_-])?"
)
RELATIVE_CANDIDATE_PATH_PATTERN: Final = (
    "^"
    + _PUBLISHED_SEGMENT
    + "(?:/"
    + _PUBLISHED_SEGMENT
    + "){0,"
    + str(MAX_PATH_SEGMENTS - 1)
    + "}$"
)


def validate_relative_candidate_path(value: str) -> str:
    """Return ``value`` when it satisfies the section 3.3 grammar, else raise.

    Purely textual: nothing is resolved, opened or normalized. Each rule raises
    its own ``ValueError`` so a rejection names the rule that fired.
    """
    if type(value) is not str:
        raise TypeError("candidate path must be a built-in string")
    if not 1 <= len(value) <= MAX_RELATIVE_PATH_CHARACTERS:
        raise ValueError(
            f"candidate path length must be 1 through {MAX_RELATIVE_PATH_CHARACTERS}"
        )
    segments = value.split("/")
    if len(segments) > MAX_PATH_SEGMENTS:
        raise ValueError(f"candidate path has more than {MAX_PATH_SEGMENTS} segments")
    for segment in segments:
        if not segment:
            raise ValueError("candidate path segment must not be empty")
        if segment in {".", ".."}:
            raise ValueError("candidate path segment must not be '.' or '..'")
        if len(segment) > MAX_SEGMENT_CHARACTERS:
            raise ValueError(
                f"candidate path segment exceeds {MAX_SEGMENT_CHARACTERS} characters"
            )
        if _SEGMENT.fullmatch(segment) is None:
            raise ValueError("candidate path segment contains a forbidden character")
        if segment.endswith("."):
            raise ValueError("candidate path segment must not end in '.'")
        if segment.partition(".")[0].upper() in _RESERVED_STEMS:
            raise ValueError(
                "candidate path segment uses a reserved Windows device name"
            )
    return value


type RelativeCandidatePath = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=MAX_RELATIVE_PATH_CHARACTERS,
    ),
    AfterValidator(validate_relative_candidate_path),
    WithJsonSchema(
        exact_string_schema(
            RELATIVE_CANDIDATE_PATH_PATTERN,
            min_length=1,
            max_length=MAX_RELATIVE_PATH_CHARACTERS,
        )
    ),
]
