"""Foundational financial and instrument records."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    StringConstraints,
    WithJsonSchema,
    model_validator,
)
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.financial import (
    CanonicalDecimal,
    NonNegativeDecimal,
    PositiveDecimal,
)
from crypto_lab.domain.identifiers import AssetCode

_INSTRUMENT_PATTERN = (
    r"^[A-Z][A-Z0-9]*(?:[._-][A-Z0-9]+)*:"
    r"[A-Z][A-Z0-9]*(?:[._-][A-Z0-9]+)*/"
    r"[A-Z][A-Z0-9]*(?:[._-][A-Z0-9]+)*:"
    r"(?:SPOT|MARGIN|FUTURES|EQUITIES)$"
)
_INSTRUMENT_PARSE_PATTERN = (
    r"^(?P<venue>[A-Z][A-Z0-9]*(?:[._-][A-Z0-9]+)*):"
    r"(?P<base>[A-Z][A-Z0-9]*(?:[._-][A-Z0-9]+)*)/"
    r"(?P<quote>[A-Z][A-Z0-9]*(?:[._-][A-Z0-9]+)*):"
    r"(?P<market>SPOT|MARGIN|FUTURES|EQUITIES)$"
)
_INSTRUMENT_COMPONENT_BOUNDS_PATTERN = (
    r"^[A-Z][A-Z0-9._-]{0,31}:"
    r"[A-Z][A-Z0-9._-]{0,31}/"
    r"[A-Z][A-Z0-9._-]{0,31}:"
    r"(?:SPOT|MARGIN|FUTURES|EQUITIES)$"
)
_INSTRUMENT_SCHEMA_PATTERN = _INSTRUMENT_PATTERN[:-1] + r"(?![\s\S])"
_INSTRUMENT_COMPONENT_BOUNDS_SCHEMA_PATTERN = (
    _INSTRUMENT_COMPONENT_BOUNDS_PATTERN[:-1] + r"(?![\s\S])"
)
_INSTRUMENT_JSON_SCHEMA: JsonSchemaValue = {
    "type": "string",
    "minLength": 10,
    "maxLength": 107,
    "allOf": [
        {"pattern": _INSTRUMENT_SCHEMA_PATTERN},
        {"pattern": _INSTRUMENT_COMPONENT_BOUNDS_SCHEMA_PATTERN},
    ],
}
_INSTRUMENT = re.compile(_INSTRUMENT_PARSE_PATTERN)


def parse_instrument_id(value: str) -> tuple[str, str, str, str]:
    """Parse one complete canonical instrument identity."""
    matched = _INSTRUMENT.fullmatch(value)
    if matched is None:
        raise ValueError("instrument_id is not canonical")
    components = (
        matched["venue"],
        matched["base"],
        matched["quote"],
        matched["market"],
    )
    if any(len(component) > 32 for component in components[:3]):
        raise ValueError("instrument components must not exceed 32 characters")
    return components


def _validate_instrument_id(value: str) -> str:
    parse_instrument_id(value)
    return value


type InstrumentId = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=10,
        max_length=107,
        pattern=_INSTRUMENT_PATTERN,
    ),
    AfterValidator(_validate_instrument_id),
    WithJsonSchema(_INSTRUMENT_JSON_SCHEMA, mode="validation"),
    WithJsonSchema(_INSTRUMENT_JSON_SCHEMA, mode="serialization"),
]


class MarketType(StrEnum):
    """Canonical market vocabulary available for descriptor compatibility."""

    SPOT = "SPOT"
    MARGIN = "MARGIN"
    FUTURES = "FUTURES"
    EQUITIES = "EQUITIES"


class InstrumentRef(CanonicalModel):
    schema_version: Literal["1.0.0"]
    canonical_id: InstrumentId
    venue: AssetCode
    base_asset: AssetCode
    quote_asset: AssetCode
    market_type: MarketType

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if self.base_asset == self.quote_asset:
            raise ValueError("base_asset and quote_asset must differ")
        expected = (
            f"{self.venue}:{self.base_asset}/{self.quote_asset}:"
            f"{self.market_type.value}"
        )
        if self.canonical_id != expected:
            raise ValueError("canonical_id does not match instrument fields")
        return self


class Money(CanonicalModel):
    schema_version: Literal["1.0.0"]
    currency: AssetCode
    amount: CanonicalDecimal


class Price(CanonicalModel):
    schema_version: Literal["1.0.0"]
    instrument_id: InstrumentId
    quote_asset: AssetCode
    value: PositiveDecimal

    @model_validator(mode="after")
    def validate_quote_asset(self) -> Self:
        _, _, quote, _ = parse_instrument_id(self.instrument_id)
        if self.quote_asset != quote:
            raise ValueError("quote_asset does not match instrument_id")
        return self


class Quantity(CanonicalModel):
    schema_version: Literal["1.0.0"]
    instrument_id: InstrumentId
    base_asset: AssetCode
    value: NonNegativeDecimal

    @model_validator(mode="after")
    def validate_base_asset(self) -> Self:
        _, base, _, _ = parse_instrument_id(self.instrument_id)
        if self.base_asset != base:
            raise ValueError("base_asset does not match instrument_id")
        return self
