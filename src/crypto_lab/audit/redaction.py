"""Field-level redaction over bounded detail trees.

Stage 9 plan Task 2 ("Interfaces produced") under specification 24.3:1774 and
30.1: the Stage 6 raw-token redaction rule re-exposed over ``JsonValue`` trees
for a package that never sees the token itself. ``audit`` imports ``domain``
alone (plan 2.6), so the attempt-token grammar is restated here as a shape --
a run of 32 or more characters of the url-safe alphabet ``[A-Za-z0-9_-]`` that
the ``AttemptToken`` type admits -- and the reviewed detail bounds and
secret-key denylist of ``domain/diagnostics.py`` are reused, not re-declared.

Three rules live here.

- ``contains_token_shape(text)``: whether a token-shaped run occurs anywhere in
  the text.
- ``redact_details(details)``: every string *value* carrying a token-shaped run,
  and every value under a denylisted key, becomes ``REDACTED``; keys, the other
  leaves and the tree shape are preserved, so the result is idempotent and
  stays within every bound its input met. Keys are governed by the domain
  bounds and denylist, not by the token grammar: an ordinary 38-character
  snake_case key is not a token.
- ``validate_bounded_details(details)``: the ``Diagnostic`` detail ceilings
  (depth, nodes, collection size, key and string length, encoded bytes, the
  denylist) and then the redaction fixed point ``redact_details(d) == d``.
  ``BoundedDetails`` carries both as the annotated type the audit records use,
  so a record never holds a value redaction would have changed.

Declared consequence (plan 7.3): a hex digest and a prefixed identifier are
token-shaped, so neither can be a detail *value*; the records carry them as
typed top-level fields instead.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Annotated, Final

from pydantic import AfterValidator, Field

from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import (
    _SECRET_KEY_COMPACT,
    _SECRET_KEY_PARTS,
    MAX_DETAIL_BYTES,
    MAX_DETAIL_COLLECTION,
    MAX_DETAIL_NODES,
    DiagnosticDetailKey,
    DiagnosticDetailValue,
    _inspect_details,
)

#: The literal every redacted value becomes: outside the token alphabet and
#: shorter than any token, so redaction is idempotent and never grows a string.
REDACTED: Final = "[REDACTED]"
#: The ``AttemptToken`` alphabet at its 32-character minimum, with no upper
#: bound: a longer run is still a leak.
TOKEN_SHAPE_PATTERN: Final = r"[A-Za-z0-9_-]{32,}"  # noqa: S105 - a grammar, not a secret
_TOKEN_SHAPE: Final = re.compile(TOKEN_SHAPE_PATTERN)
_CAMEL_BOUNDARY: Final = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_ALPHANUMERIC: Final = re.compile(r"[^a-z0-9]+")


def contains_token_shape(text: str) -> bool:
    """Whether ``text`` carries a run of 32 or more url-safe characters."""
    if type(text) is not str:
        raise TypeError("text must be a built-in string")
    return _TOKEN_SHAPE.search(text) is not None


def is_denylisted_key(key: str) -> bool:
    """The ``_inspect_details`` secret-key rule applied to one key.

    The same normalization, word for word: a camel-case boundary becomes an
    underscore, the key is case-folded, every non-alphanumeric run becomes one
    underscore, and the padded form is matched against the word denylist while
    the compacted form is matched against the compact denylist. Pinned equal to
    the domain refusal by test.
    """
    if type(key) is not str:
        raise TypeError("detail key must be a built-in string")
    separated = _CAMEL_BOUNDARY.sub("_", key)
    normalized = _NON_ALPHANUMERIC.sub("_", separated.casefold()).strip("_")
    padded = f"_{normalized}_"
    compact = _NON_ALPHANUMERIC.sub("", key.casefold())
    return any(f"_{part}_" in padded for part in _SECRET_KEY_PARTS) or any(
        part in compact for part in _SECRET_KEY_COMPACT
    )


def _redact_value(value: DiagnosticDetailValue) -> DiagnosticDetailValue:
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, str):
        return REDACTED if _TOKEN_SHAPE.search(value) is not None else value
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, dict):
        return _redact_object(value)
    raise ValueError("unsupported detail value")


def _redact_object(
    value: Mapping[str, DiagnosticDetailValue],
) -> dict[str, DiagnosticDetailValue]:
    redacted: dict[str, DiagnosticDetailValue] = {}
    for key, nested in value.items():
        if type(key) is not str:
            raise TypeError("detail key must be a built-in string")
        redacted[key] = REDACTED if is_denylisted_key(key) else _redact_value(nested)
    return redacted


def redact_details(details: Mapping[str, DiagnosticDetailValue]) -> BoundedDetails:
    """Return the redacted copy of ``details``; the input is never mutated."""
    if not isinstance(details, Mapping):
        raise TypeError("details must be a mapping")
    return _redact_object(details)


def validate_bounded_details(
    value: dict[DiagnosticDetailKey, DiagnosticDetailValue],
) -> dict[DiagnosticDetailKey, DiagnosticDetailValue]:
    """The ``Diagnostic`` detail ceilings, then the redaction fixed point."""
    nodes = _inspect_details(value)
    if nodes > MAX_DETAIL_NODES:
        raise ValueError("details contain too many nodes")
    if len(canonical_json_bytes(value)) > MAX_DETAIL_BYTES:
        raise ValueError("details exceed maximum encoded bytes")
    if redact_details(value) != value:
        raise ValueError("details must be a redaction fixed point")
    return value


type BoundedDetails = Annotated[
    dict[DiagnosticDetailKey, DiagnosticDetailValue],
    Field(max_length=MAX_DETAIL_COLLECTION),
    AfterValidator(validate_bounded_details),
]


__all__ = (
    "REDACTED",
    "TOKEN_SHAPE_PATTERN",
    "BoundedDetails",
    "contains_token_shape",
    "is_denylisted_key",
    "redact_details",
    "validate_bounded_details",
)
