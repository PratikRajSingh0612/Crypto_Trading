"""Canonical Decimal validation and fixed-point serialization."""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Annotated

from pydantic import (
    AfterValidator,
    BeforeValidator,
    PlainSerializer,
    ValidationInfo,
    WithJsonSchema,
)

MAX_DECIMAL_TEXT_LENGTH = 256
CANONICAL_DECIMAL_PATTERN = (
    r"^(?:0|[1-9][0-9]*(?:\.[0-9]*[1-9])?|0\.[0-9]*[1-9]|"
    r"-[1-9][0-9]*(?:\.[0-9]*[1-9])?|-0\.[0-9]*[1-9])$"
)
POSITIVE_DECIMAL_PATTERN = r"^(?:[1-9][0-9]*(?:\.[0-9]*[1-9])?|0\.[0-9]*[1-9])$"
NON_NEGATIVE_DECIMAL_PATTERN = r"^(?:0|[1-9][0-9]*(?:\.[0-9]*[1-9])?|0\.[0-9]*[1-9])$"


def format_decimal(value: Decimal) -> str:
    """Render a finite Decimal without ambient-context normalization."""
    if not value.is_finite():
        raise ValueError("decimal must be finite")
    if value.is_zero():
        if value.is_signed():
            raise ValueError("negative zero is forbidden")
        return "0"
    sign, raw_digits, raw_exponent = value.as_tuple()
    if not isinstance(raw_exponent, int):
        raise ValueError("decimal must be finite")
    trailing_zeroes = 0
    for digit in reversed(raw_digits):
        if digit != 0:
            break
        trailing_zeroes += 1
    significant_digits = (
        raw_digits[:-trailing_zeroes] if trailing_zeroes else raw_digits
    )
    exponent = raw_exponent + trailing_zeroes
    coefficient_length = len(significant_digits)
    if exponent >= 0:
        body_length = coefficient_length + exponent
    else:
        point = coefficient_length + exponent
        body_length = (
            2 - point + coefficient_length if point <= 0 else coefficient_length + 1
        )
    if sign + body_length > MAX_DECIMAL_TEXT_LENGTH:
        raise ValueError("canonical decimal exceeds maximum length")
    digits = "".join(str(digit) for digit in significant_digits)
    if exponent >= 0:
        rendered = digits + ("0" * exponent)
    else:
        point = len(digits) + exponent
        if point <= 0:
            rendered = "0." + ("0" * -point) + digits
        else:
            rendered = digits[:point] + "." + digits[point:]
        rendered = rendered.rstrip("0").rstrip(".")
    return f"-{rendered}" if sign else rendered


def parse_decimal(value: object, info: ValidationInfo) -> Decimal:
    """Accept typed Decimal in Python mode and canonical strings in JSON."""
    if info.mode == "python":
        if not isinstance(value, Decimal):
            raise ValueError("Python input must be Decimal")
        parsed = value
    else:
        if not isinstance(value, str):
            raise ValueError("JSON decimal input must be a string")
        if len(value) > MAX_DECIMAL_TEXT_LENGTH:
            raise ValueError("decimal string exceeds maximum length")
        if re.fullmatch(CANONICAL_DECIMAL_PATTERN, value) is None:
            raise ValueError("JSON decimal string is not canonical")
        parsed = Decimal(value)
    rendered = format_decimal(parsed)
    if len(rendered) > MAX_DECIMAL_TEXT_LENGTH:
        raise ValueError("canonical decimal exceeds maximum length")
    return parsed


def require_positive(value: Decimal) -> Decimal:
    if value <= 0:
        raise ValueError("decimal must be positive")
    return value


def require_non_negative(value: Decimal) -> Decimal:
    if value < 0:
        raise ValueError("decimal must be non-negative")
    return value


def _schema(pattern: str, description: str) -> dict[str, object]:
    return {
        "type": "string",
        "pattern": pattern[:-1] + r"(?![\s\S])",
        "maxLength": MAX_DECIMAL_TEXT_LENGTH,
        "description": description,
    }


type CanonicalDecimal = Annotated[
    Decimal,
    BeforeValidator(parse_decimal),
    PlainSerializer(format_decimal, return_type=str, when_used="json"),
    WithJsonSchema(
        _schema(CANONICAL_DECIMAL_PATTERN, "Canonical finite Decimal string"),
        mode="validation",
    ),
    WithJsonSchema(
        _schema(CANONICAL_DECIMAL_PATTERN, "Canonical finite Decimal string"),
        mode="serialization",
    ),
]
type PositiveDecimal = Annotated[
    CanonicalDecimal,
    AfterValidator(require_positive),
    WithJsonSchema(
        _schema(POSITIVE_DECIMAL_PATTERN, "Canonical positive Decimal string"),
        mode="validation",
    ),
    WithJsonSchema(
        _schema(POSITIVE_DECIMAL_PATTERN, "Canonical positive Decimal string"),
        mode="serialization",
    ),
]
type NonNegativeDecimal = Annotated[
    CanonicalDecimal,
    AfterValidator(require_non_negative),
    WithJsonSchema(
        _schema(
            NON_NEGATIVE_DECIMAL_PATTERN,
            "Canonical non-negative Decimal string",
        ),
        mode="validation",
    ),
    WithJsonSchema(
        _schema(
            NON_NEGATIVE_DECIMAL_PATTERN,
            "Canonical non-negative Decimal string",
        ),
        mode="serialization",
    ),
]
