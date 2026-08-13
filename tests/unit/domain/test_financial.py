from __future__ import annotations

import json
from decimal import Decimal, localcontext

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import TypeAdapter, ValidationError

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.financial import (
    CanonicalDecimal,
    NonNegativeDecimal,
    PositiveDecimal,
    format_decimal,
)


class DecimalProbe(CanonicalModel):
    value: CanonicalDecimal


class PositiveProbe(CanonicalModel):
    value: PositiveDecimal


class NonNegativeProbe(CanonicalModel):
    value: NonNegativeDecimal


_DECIMAL_ADAPTERS: list[TypeAdapter[Decimal]] = [
    TypeAdapter(CanonicalDecimal),
    TypeAdapter(PositiveDecimal),
    TypeAdapter(NonNegativeDecimal),
]


@pytest.mark.parametrize(
    ("value", "encoded"),
    [
        (Decimal("0"), '{"value":"0"}'),
        (Decimal("1E+3"), '{"value":"1000"}'),
        (Decimal("1.2300"), '{"value":"1.23"}'),
        (Decimal("-0.00100"), '{"value":"-0.001"}'),
    ],
)
def test_typed_decimal_serializes_as_canonical_fixed_point(
    value: Decimal,
    encoded: str,
) -> None:
    model = DecimalProbe(value=value)
    assert model.model_dump_json() == encoded
    assert DecimalProbe.model_validate_json(encoded) == model


@pytest.mark.parametrize("value", [0, 1, 1.0, True, "1.23", None])
def test_python_mode_rejects_every_non_decimal(value: object) -> None:
    with pytest.raises((TypeError, ValidationError)):
        DecimalProbe.model_validate({"value": value})


@pytest.mark.parametrize(
    "document",
    [
        '{"value":1.23}',
        '{"value":"1E+3"}',
        '{"value":"1.2300"}',
        '{"value":"1.0"}',
        '{"value":"+1"}',
        '{"value":"01"}',
        '{"value":"-0"}',
        '{"value":"-0.0"}',
        '{"value":"NaN"}',
        '{"value":"Infinity"}',
        '{"value":""}',
        '{"value":" 1"}',
    ],
)
def test_json_mode_rejects_noncanonical_decimal_forms(document: str) -> None:
    with pytest.raises((TypeError, ValidationError)):
        DecimalProbe.model_validate_json(document)


@pytest.mark.parametrize(
    "value",
    [Decimal("-0"), Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")],
)
def test_typed_decimal_rejects_noncanonical_special_values(
    value: Decimal,
) -> None:
    with pytest.raises(ValidationError):
        DecimalProbe(value=value)


def test_sign_constrained_aliases() -> None:
    assert PositiveProbe(value=Decimal("0.1")).value == Decimal("0.1")
    assert NonNegativeProbe(value=Decimal("0")).value == Decimal("0")
    with pytest.raises(ValidationError):
        PositiveProbe(value=Decimal("0"))
    with pytest.raises(ValidationError):
        NonNegativeProbe(value=Decimal("-0.1"))


def test_formatting_is_independent_of_decimal_context() -> None:
    with localcontext() as context:
        context.prec = 2
        assert format_decimal(Decimal("123456789.1234500")) == "123456789.12345"


def test_extreme_exponent_is_rejected_before_render_allocation() -> None:
    with pytest.raises(ValidationError, match="maximum length"):
        DecimalProbe(value=Decimal("1E+100000000"))


@pytest.mark.parametrize("adapter", _DECIMAL_ADAPTERS)
def test_decimal_json_schemas_are_string_only(
    adapter: TypeAdapter[Decimal],
) -> None:
    schemas = (
        adapter.json_schema(mode="validation"),
        adapter.json_schema(mode="serialization"),
    )
    for schema in schemas:
        assert schema["type"] == "string"
        assert schema["pattern"].endswith(r"(?![\s\S])")
        assert "maxLength" in schema
        validator = Draft202012Validator(schema)
        validator.validate("1")
        for terminator in ("\n", "\r", "\r\n"):
            with pytest.raises(ValidationError):
                adapter.validate_json(json.dumps("1" + terminator))
            with pytest.raises(JsonSchemaValidationError):
                validator.validate("1" + terminator)
