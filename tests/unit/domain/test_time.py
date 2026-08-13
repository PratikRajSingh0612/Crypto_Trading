from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import TypeAdapter, ValidationError

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.time import UtcDateTime, format_utc


class UtcProbe(CanonicalModel):
    value: UtcDateTime


def test_utc_python_and_json_round_trip_are_canonical() -> None:
    seconds = UtcProbe(value=datetime(2026, 8, 10, 1, 2, 3, tzinfo=UTC))
    micros = UtcProbe(value=datetime(2026, 8, 10, 1, 2, 3, 42, tzinfo=UTC))
    assert seconds.model_dump_json() == '{"value":"2026-08-10T01:02:03Z"}'
    assert micros.model_dump_json() == ('{"value":"2026-08-10T01:02:03.000042Z"}')
    assert UtcProbe.model_validate_json(seconds.model_dump_json()) == seconds
    assert format_utc(seconds.value) == "2026-08-10T01:02:03Z"


@pytest.mark.parametrize(
    "value",
    [
        datetime(2026, 8, 10, 1, 2, 3),  # noqa: DTZ001 - deliberate rejection case
        datetime(
            2026,
            8,
            10,
            1,
            2,
            3,
            tzinfo=timezone(timedelta(hours=5, minutes=30)),
        ),
        "2026-08-10T01:02:03Z",
    ],
)
def test_python_validation_rejects_non_typed_or_non_utc_values(
    value: object,
) -> None:
    with pytest.raises(ValidationError):
        UtcProbe.model_validate({"value": value})


@pytest.mark.parametrize(
    "value",
    [
        datetime(2026, 8, 10, 1, 2, 3),  # noqa: DTZ001 - rejection case
        datetime(
            2026,
            8,
            10,
            1,
            2,
            3,
            tzinfo=timezone(timedelta(hours=1)),
        ),
    ],
)
def test_format_utc_rejects_naive_and_nonzero_offset_values(value: datetime) -> None:
    with pytest.raises(ValueError, match="UTC"):
        format_utc(value)


@pytest.mark.parametrize(
    "document",
    [
        '{"value":"2026-02-30T01:02:03Z"}',
        '{"value":"2026-08-10T01:02:03+00:00"}',
        '{"value":"2026-08-10T01:02:03.1Z"}',
    ],
)
def test_json_validation_rejects_noncanonical_utc_text(document: str) -> None:
    with pytest.raises(ValidationError):
        UtcProbe.model_validate_json(document)


def test_utc_schema_requires_the_exact_z_form() -> None:
    adapter: TypeAdapter[datetime] = TypeAdapter(UtcDateTime)
    schemas = (
        adapter.json_schema(mode="validation"),
        adapter.json_schema(mode="serialization"),
    )
    for schema in schemas:
        assert schema["type"] == "string"
        assert schema["format"] == "date-time"
        assert schema["pattern"].endswith(r"Z(?![\s\S])")
        validator = Draft202012Validator(schema)
        validator.validate("2026-08-10T01:02:03Z")
        for terminator in ("\n", "\r", "\r\n"):
            with pytest.raises(ValidationError):
                adapter.validate_json(json.dumps("2026-08-10T01:02:03Z" + terminator))
            with pytest.raises(JsonSchemaValidationError):
                validator.validate("2026-08-10T01:02:03Z" + terminator)
