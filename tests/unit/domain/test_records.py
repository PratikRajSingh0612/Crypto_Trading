from __future__ import annotations

from decimal import Decimal

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import TypeAdapter, ValidationError

from crypto_lab.domain.records import (
    InstrumentId,
    InstrumentRef,
    MarketType,
    Money,
    Price,
    Quantity,
    parse_instrument_id,
)

_INSTRUMENT = "BINANCE:BTC/USDT:SPOT"


def _instrument() -> InstrumentRef:
    return InstrumentRef(
        schema_version="1.0.0",
        canonical_id=_INSTRUMENT,
        venue="BINANCE",
        base_asset="BTC",
        quote_asset="USDT",
        market_type=MarketType.SPOT,
    )


def test_instrument_id_is_a_strict_canonical_boundary() -> None:
    adapter: TypeAdapter[str] = TypeAdapter(InstrumentId)
    assert adapter.validate_python(_INSTRUMENT) == _INSTRUMENT
    for invalid in (
        "BINANCE:BTC-USDT:SPOT",
        "BINANCE:BTC/USDT:UNKNOWN",
        "BINANCE::BTC/USDT:SPOT",
        "BINANCE:BTC//USDT:SPOT",
        "binance:BTC/USDT:SPOT",
        "BINANCE:_BTC/USDT:SPOT",
    ):
        with pytest.raises(ValidationError):
            adapter.validate_python(invalid)
    with pytest.raises(ValidationError):
        adapter.validate_python(1)


@pytest.mark.parametrize(
    ("valid", "invalid"),
    [
        (
            f"{'A' * 32}:BTC/USDT:SPOT",
            f"{'A' * 33}:BTC/USDT:SPOT",
        ),
        (
            f"BINANCE:{'A' * 32}/USDT:SPOT",
            f"BINANCE:{'A' * 33}/USDT:SPOT",
        ),
        (
            f"BINANCE:BTC/{'A' * 32}:SPOT",
            f"BINANCE:BTC/{'A' * 33}:SPOT",
        ),
    ],
)
def test_instrument_id_enforces_each_component_length(
    valid: str,
    invalid: str,
) -> None:
    adapter: TypeAdapter[str] = TypeAdapter(InstrumentId)
    assert adapter.validate_python(valid) == valid
    with pytest.raises(ValidationError, match="32 characters"):
        adapter.validate_python(invalid)


def test_instrument_id_json_schemas_enforce_component_bounds() -> None:
    adapter: TypeAdapter[str] = TypeAdapter(InstrumentId)
    schemas = (
        adapter.json_schema(mode="validation"),
        adapter.json_schema(mode="serialization"),
    )
    invalid = [
        "BINANCE:BTC-USDT:SPOT",
        "BINANCE:BTC/USDT:UNKNOWN",
        "BINANCE::BTC/USDT:SPOT",
        "BINANCE:BTC//USDT:SPOT",
        "binance:BTC/USDT:SPOT",
        "BINANCE:_BTC/USDT:SPOT",
        f"{'A' * 33}:BTC/USDT:SPOT",
        f"BINANCE:{'A' * 33}/USDT:SPOT",
        f"BINANCE:BTC/{'A' * 33}:SPOT",
    ]
    invalid.extend(_INSTRUMENT + terminator for terminator in ("\n", "\r", "\r\n"))
    for schema in schemas:
        assert schema["type"] == "string"
        assert schema["minLength"] == 10
        assert schema["maxLength"] == 107
        assert len(schema["allOf"]) == 2
        patterns = [branch["pattern"] for branch in schema["allOf"]]
        assert all("(?P<" not in pattern for pattern in patterns)
        assert all("(?=" not in pattern for pattern in patterns)
        validator = Draft202012Validator(schema)
        validator.validate(_INSTRUMENT)
        for value in invalid:
            with pytest.raises(ValidationError):
                adapter.validate_python(value)
            with pytest.raises(JsonSchemaValidationError):
                validator.validate(value)


def test_instrument_ref_reconstructs_exact_identity() -> None:
    instrument = _instrument()
    assert parse_instrument_id(instrument.canonical_id) == (
        "BINANCE",
        "BTC",
        "USDT",
        "SPOT",
    )
    assert InstrumentRef.model_validate_json(instrument.model_dump_json()) == instrument


@pytest.mark.parametrize(
    "update",
    [
        {"canonical_id": "BINANCE:ETH/USDT:SPOT"},
        {"canonical_id": "BINANCE:BTC-USDT:SPOT"},
        {"market_type": "UNKNOWN"},
    ],
)
def test_instrument_ref_rejects_inconsistent_or_foreign_fields(
    update: dict[str, object],
) -> None:
    payload = _instrument().model_dump(mode="python")
    payload.update(update)
    with pytest.raises(ValidationError):
        InstrumentRef.model_validate(payload)


def test_instrument_ref_rejects_same_base_and_quote() -> None:
    payload = _instrument().model_dump(mode="python")
    payload.update(
        {
            "canonical_id": "BINANCE:BTC/BTC:SPOT",
            "quote_asset": "BTC",
        }
    )
    with pytest.raises(
        ValidationError,
        match="base_asset and quote_asset must differ",
    ):
        InstrumentRef.model_validate(payload)


def test_instrument_ref_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        InstrumentRef.model_validate(
            {
                **_instrument().model_dump(mode="python"),
                "unexpected": "rejected",
            }
        )


def test_money_price_and_quantity_round_trip() -> None:
    money = Money(
        schema_version="1.0.0",
        currency="USDT",
        amount=Decimal("-1.25"),
    )
    price = Price(
        schema_version="1.0.0",
        instrument_id=_INSTRUMENT,
        quote_asset="USDT",
        value=Decimal("65000.25"),
    )
    quantity = Quantity(
        schema_version="1.0.0",
        instrument_id=_INSTRUMENT,
        base_asset="BTC",
        value=Decimal("0"),
    )
    assert Money.model_validate_json(money.model_dump_json()) == money
    assert Price.model_validate_json(price.model_dump_json()) == price
    assert Quantity.model_validate_json(quantity.model_dump_json()) == quantity


@pytest.mark.parametrize(
    ("model_type", "payload"),
    [
        (
            Money,
            {"schema_version": "1.0.0", "currency": "USDT", "amount": 1.0},
        ),
        (
            Price,
            {
                "schema_version": "1.0.0",
                "instrument_id": _INSTRUMENT,
                "quote_asset": "USDT",
                "value": Decimal("0"),
            },
        ),
        (
            Price,
            {
                "schema_version": "1.0.0",
                "instrument_id": _INSTRUMENT,
                "quote_asset": "USDT",
                "value": Decimal("-1"),
            },
        ),
        (
            Price,
            {
                "schema_version": "1.0.0",
                "instrument_id": _INSTRUMENT,
                "quote_asset": "BTC",
                "value": Decimal("1"),
            },
        ),
        (
            Quantity,
            {
                "schema_version": "1.0.0",
                "instrument_id": _INSTRUMENT,
                "base_asset": "BTC",
                "value": Decimal("-0.1"),
            },
        ),
        (
            Quantity,
            {
                "schema_version": "1.0.0",
                "instrument_id": _INSTRUMENT,
                "base_asset": "USDT",
                "value": Decimal("1"),
            },
        ),
    ],
)
def test_financial_records_reject_invalid_values(
    model_type: type[Money] | type[Price] | type[Quantity],
    payload: dict[str, object],
) -> None:
    with pytest.raises((TypeError, ValidationError)):
        model_type.model_validate(payload)


def test_money_rejects_noncanonical_json_decimal_string() -> None:
    with pytest.raises(ValidationError):
        Money.model_validate_json(
            '{"schema_version":"1.0.0","currency":"USDT","amount":"1.0"}'
        )


@pytest.mark.parametrize("model_type", [Price, Quantity])
def test_instrument_linked_records_reject_malformed_instrument_id(
    model_type: type[Price] | type[Quantity],
) -> None:
    payload = {
        "schema_version": "1.0.0",
        "instrument_id": "BINANCE:BTC-USDT:SPOT",
        "value": Decimal("1"),
    }
    if model_type is Price:
        payload["quote_asset"] = "USDT"
    else:
        payload["base_asset"] = "BTC"
    with pytest.raises(ValidationError):
        model_type.model_validate(payload)


@pytest.mark.parametrize(
    "model",
    [
        Money(schema_version="1.0.0", currency="USDT", amount=Decimal("1")),
        Price(
            schema_version="1.0.0",
            instrument_id=_INSTRUMENT,
            quote_asset="USDT",
            value=Decimal("1"),
        ),
        Quantity(
            schema_version="1.0.0",
            instrument_id=_INSTRUMENT,
            base_asset="BTC",
            value=Decimal("1"),
        ),
    ],
)
def test_financial_records_reject_unknown_fields(
    model: Money | Price | Quantity,
) -> None:
    payload = model.model_dump(mode="python")
    payload["unexpected"] = "rejected"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        type(model).model_validate(payload)
