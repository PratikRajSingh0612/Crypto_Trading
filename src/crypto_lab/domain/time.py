"""Canonical timezone-aware UTC values and the process-local monotonic instant."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from pydantic import BeforeValidator, PlainSerializer, ValidationInfo, WithJsonSchema

_UTC_PATTERN = (
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{6})?Z$"
)
_UTC_SCHEMA_PATTERN = _UTC_PATTERN[:-1] + r"(?![\s\S])"
_UTC_SCHEMA = {
    "type": "string",
    "format": "date-time",
    "pattern": _UTC_SCHEMA_PATTERN,
}

# Forward-only schema projection, deliberately not applied to `_UTC_SCHEMA`.
#
# `parse_utc` routes JSON text through `datetime.fromisoformat`, so the runtime
# has always rejected an impossible calendar date (`2026-02-30`, `2026-13-01`,
# `2026-04-31`, a non-leap `2025-02-29`) and an out-of-range clock (`T24:00:00`,
# `T00:60:00`, `T00:00:60`). `_UTC_SCHEMA` publishes only `[0-9]{2}` runs, so a
# standards-compliant Draft 2020-12 validator accepts all of them. Both halves of
# that gap are exactly expressible, and neither can be closed in place:
# `$defs/UtcDateTime` is already published in three released Stage 3 `$id`s --
# `datasets/dataset-descriptor-v1`, `datasets/dataset-partition-v1`, and
# `domain/diagnostic-v1` -- and tightening the shared projection would move
# permanent bytes for all three.
#
# `CalendarValidUtcDateTime` below is therefore a second *schema view* over the
# same runtime type: same parser, same UTC rule, same serializer, same canonical
# JSON, strictly narrower published grammar. It exists for Stage 4 artifacts that
# have not been released yet, and it is applied at the field.

# Gregorian date, anchored at the start and ending at the `T` separator. Years
# `0001`-`9999`; 31-day and 30-day months by name; February capped at 28 except
# on a leap year, which is a year divisible by four whose last two digits are
# nonzero, or a century whose century part is itself divisible by four. Only
# `[0-9]` classes and `(?:...)` groups, so the pattern is ECMA-262 and Python
# `re` compatible with identical semantics.
_CALENDAR_DATE_PREFIX_PATTERN = (
    r"^(?:"
    r"(?:"
    r"[0-9]{3}[1-9]|"
    r"[0-9]{2}[1-9][0-9]|"
    r"[0-9][1-9][0-9]{2}|"
    r"[1-9][0-9]{3}"
    r")-"
    r"(?:"
    r"(?:0[13578]|1[02])-(?:0[1-9]|[12][0-9]|3[01])|"
    r"(?:0[469]|11)-(?:0[1-9]|[12][0-9]|30)|"
    r"02-(?:0[1-9]|1[0-9]|2[0-8])"
    r")|"
    r"(?:"
    r"[0-9]{2}(?:0[48]|[2468][048]|[13579][26])|"
    r"(?:0[48]|[2468][048]|[13579][26])00"
    r")-02-29"
    r")T"
)

# Clock, anchored at the start so it cannot float: hour `00`-`23`, minute and
# second `00`-`59`, then the existing optional six-digit fraction and uppercase
# `Z`. The fraction separator is an escaped `\.`, never a bare `.` -- a bare dot
# would publish "any character" as the separator. Exact end-of-string is owned by
# the legacy branch's `(?![\s\S])` and inherited through the `allOf` conjunction,
# which `test_the_forward_view_terminates_on_the_exact_string` measures rather
# than assumes; a `$` here would be inexact under a Python-backed validator,
# where `$` also matches before a trailing newline.
_CLOCK_TIME_PREFIX_PATTERN = (
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]{6})?Z"
)

# Additive: branch 0 is the released projection verbatim, so every rule it
# already carried -- fractional seconds, uppercase `Z`, length, exact
# termination -- stays in force and stays owned by one place. `dict(...)` copies
# the frozen projection so no consumer post-processing a branch can reach the
# object the three Stage 3 schemas render from.
_CALENDAR_VALID_UTC_SCHEMA: dict[str, Any] = {
    "allOf": [
        dict(_UTC_SCHEMA),
        {"type": "string", "pattern": _CALENDAR_DATE_PREFIX_PATTERN},
        {"type": "string", "pattern": _CLOCK_TIME_PREFIX_PATTERN},
    ]
}


def require_utc(value: datetime) -> datetime:
    """Accept UTC only and reject naive or nonzero-offset values."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware UTC")
    if value.utcoffset() != timedelta(0):
        raise ValueError("timestamp offset must be UTC")
    return value.astimezone(UTC)


def format_utc(value: datetime) -> str:
    """Serialize UTC with Z and deterministic fractional seconds."""
    normalized = require_utc(value)
    timespec = "seconds" if normalized.microsecond == 0 else "microseconds"
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


def parse_utc(value: object, info: ValidationInfo) -> datetime:
    """Accept typed UTC datetimes in Python and canonical Z text in JSON."""
    if info.mode == "python":
        if not isinstance(value, datetime):
            raise ValueError("Python input must be a datetime")
        return require_utc(value)
    if not isinstance(value, str) or re.fullmatch(_UTC_PATTERN, value) is None:
        raise ValueError("JSON timestamp is not canonical UTC text")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise ValueError("JSON timestamp is not a valid datetime") from error
    return require_utc(parsed)


type UtcDateTime = Annotated[
    datetime,
    BeforeValidator(parse_utc),
    PlainSerializer(format_utc, return_type=str, when_used="json"),
    WithJsonSchema(_UTC_SCHEMA, mode="validation"),
    WithJsonSchema(_UTC_SCHEMA, mode="serialization"),
]

type CalendarValidUtcDateTime = Annotated[
    UtcDateTime,
    WithJsonSchema(_CALENDAR_VALID_UTC_SCHEMA, mode="validation"),
    WithJsonSchema(_CALENDAR_VALID_UTC_SCHEMA, mode="serialization"),
]
"""`UtcDateTime` with a calendar- and clock-exact published grammar.

Identical runtime: the same `parse_utc` validator, the same `require_utc` UTC
rule, the same `format_utc` serializer, the same `datetime` output, and the same
canonical JSON bytes. The only difference is the JSON Schema projection, which
narrows the published date to a real Gregorian calendar date and the published
clock to `00:00:00`-`23:59:59`.

Use this at every Stage 4 timestamp field that reaches a **published** schema.
Import it from `crypto_lab.domain.time` directly: `crypto_lab.domain` re-exports
only the legacy alias, and widening that package's public surface belongs to
whoever owns `domain/__init__.py`. The rule is enforced by
`test_every_published_stage_four_timestamp_uses_the_forward_view`, not by this
sentence.

`UtcDateTime` is retained unchanged because its looser projection is already
published in three released Stage 3 `$id`s, and a published `$id` is a permanent
contract. One Stage 4 field deliberately stays on it: `Bar.timestamp_utc` in
`strategy/evaluation.py`, which no registry entry reaches and which therefore
carries no permanent `$id`. That exemption is exactly why the rule above is
scoped to published schemas rather than to every field, and the guard test fails
the moment `Bar` — or anything else still on the legacy alias — is registered.
"""

_INFINITE_SECONDS = (float("inf"), float("-inf"))


@dataclass(frozen=True, slots=True, order=True)
class MonotonicInstant:
    """A reading of the process-local monotonic clock, in seconds (spec 14.8).

    The companion of the UTC instant ``Clock.now_utc`` returns: one paired
    observation at the ``PENDING`` to ``STARTING`` swap yields the durable UTC
    deadline and this reading, from which the live supervisor derives the
    monotonic deadline that governs it. A monotonic reading is never persisted,
    serialized, hashed or compared across restarts, and it is not a Pydantic
    field anywhere (Stage 7 plan sections 2.4 and 3.2). The value is an exact
    ``float`` of non-negative finite seconds; an ``int`` or ``bool`` reading is
    refused because it is not a clock reading.
    """

    seconds: float

    def __post_init__(self) -> None:
        if type(self.seconds) is not float or self.seconds != self.seconds:
            raise ValueError("a monotonic instant is a finite float of seconds")
        if self.seconds in _INFINITE_SECONDS or self.seconds < 0.0:
            raise ValueError("a monotonic instant is finite and never negative")

    def plus(self, seconds: float) -> MonotonicInstant:
        """Return the instant ``seconds`` later.

        The offset is a finite, non-negative duration; an ``int`` is accepted
        because the record's ``timeout_seconds`` is one (Stage 7 plan 6.1), a
        ``bool`` is not. A sum that leaves the finite range fails closed.
        """
        if isinstance(seconds, bool) or not isinstance(seconds, int | float):
            raise ValueError("a monotonic instant offset is a number of seconds")
        if seconds != seconds or seconds in _INFINITE_SECONDS or seconds < 0:
            raise ValueError("a monotonic instant offset is finite and never negative")
        try:
            offset = float(seconds)
        except OverflowError as error:
            raise ValueError(
                "a monotonic instant offset is finite and never negative"
            ) from error
        return MonotonicInstant(self.seconds + offset)

    def until(self, other: MonotonicInstant) -> float:
        """Return the signed seconds from this reading to ``other``."""
        return other.seconds - self.seconds
