"""Canonical timezone-aware UTC values."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Annotated

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
