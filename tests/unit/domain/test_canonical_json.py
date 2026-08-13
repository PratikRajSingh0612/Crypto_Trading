from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from enum import IntEnum, StrEnum

import pytest
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import (
    canonical_json_bytes,
    canonical_json_text,
)
from crypto_lab.domain.hashing import sha256_bytes


class ExampleEnum(StrEnum):
    VALUE = "VALUE"


class IntegerEnum(IntEnum):
    VALUE = 1


class StringSubclass(str):
    pass


class NullableOrMissingProbe(CanonicalModel):
    value: str | MISSING | None = MISSING  # type: ignore[valid-type]


def test_canonical_json_matches_the_golden_byte_profile() -> None:
    value = {
        "z": [True, 2, "é"],
        "a": Decimal("1.2300"),
        "enum": ExampleEnum.VALUE,
        "nested": {"time": datetime(2026, 8, 10, 1, 2, 3, tzinfo=UTC)},
    }
    expected = (
        '{"a":"1.23","enum":"VALUE","nested":'
        '{"time":"2026-08-10T01:02:03Z"},"z":[true,2,"é"]}'
    )
    assert canonical_json_text(value) == expected
    assert canonical_json_bytes(value) == expected.encode("utf-8")


def test_object_key_order_is_irrelevant_and_array_order_is_material() -> None:
    left = {"b": {"d": 2, "c": 1}, "a": [1, 2]}
    right = {"a": [1, 2], "b": {"c": 1, "d": 2}}
    assert canonical_json_bytes(left) == canonical_json_bytes(right)
    assert canonical_json_bytes({"a": [1, 2]}) != canonical_json_bytes({"a": [2, 1]})


def test_explicit_null_is_material_while_missing_is_omitted() -> None:
    explicit_null = canonical_json_bytes(NullableOrMissingProbe(value=None))
    omitted = canonical_json_bytes(NullableOrMissingProbe())

    assert explicit_null == b'{"value":null}'
    assert omitted == b"{}"
    assert sha256_bytes(explicit_null) == (
        "1c197daef20de3f47eec5e2f735ec6669869d3180cc29f35be4788511e0af0f8"
    )
    assert sha256_bytes(omitted) == (
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    )
    assert sha256_bytes(explicit_null) != sha256_bytes(omitted)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (1.0, "float is forbidden"),
        (b"bytes", "unsupported canonical JSON type"),
        ({1, 2}, "unsupported canonical JSON type"),
        (object(), "unsupported canonical JSON type"),
        (IntegerEnum.VALUE, "unsupported canonical JSON type"),
        ({1: "non-string-key"}, "keys must be strings"),
        ({StringSubclass("key"): "subclass-key"}, "keys must be strings"),
        ({ExampleEnum.VALUE: "enum-key"}, "keys must be strings"),
        (
            datetime(2026, 8, 10, 1, 2, 3),  # noqa: DTZ001 - rejection case
            "timezone-aware UTC",
        ),
        (
            datetime(
                2026,
                8,
                10,
                1,
                2,
                3,
                tzinfo=timezone(timedelta(hours=1)),
            ),
            "offset must be UTC",
        ),
    ],
)
def test_unsupported_values_are_rejected_before_json_coercion(
    value: object,
    message: str,
) -> None:
    with pytest.raises((TypeError, ValueError), match=message):
        canonical_json_bytes(value)


def test_cycles_are_rejected() -> None:
    cyclic: list[object] = []
    cyclic.append(cyclic)
    with pytest.raises(ValueError, match="cyclic canonical value"):
        canonical_json_bytes(cyclic)
